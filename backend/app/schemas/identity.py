"""
AuditGraph Identity Schemas (Pydantic v2)

Canonical contract for identity-centric data flowing through the AuditGraph
platform. These schemas are the single source of truth for the B01-B09 blocks
that compose an IdentityState, and they enforce the F1 (stable cross-cloud
identity UUID) and F3 (data context provenance) patches.

Design rules enforced here:
  * organization_id is MANDATORY on every BaseModel (multi-tenant safety).
  * Role usage is EMBEDDED on each RoleAssignment — never a side dict.
  * Attack-path targets are typed Resource objects — never raw string paths.
  * DataContext is a dataclass (lightweight, immutable provenance carrier)
    and is propagated onto every IdentityProfile / IdentityState.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class _CaseInsensitiveMixin:
    """Mixin that adds case-insensitive ``_missing_`` resolution to str Enums.

    Placed on enums whose canonical values use Title/PascalCase but which
    must also accept lowercase from query params and legacy DB rows.
    """

    @classmethod
    def _missing_(cls, value: object) -> "Enum | None":
        if not isinstance(value, str):
            return None
        lowered = value.lower()
        for member in cls:
            if member.value.lower() == lowered:
                return member
        return None


class IdentityType(str, Enum):
    HUMAN_USER = "human_user"
    GUEST_USER = "guest_user"
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    APP_REGISTRATION = "app_registration"
    AI_AGENT = "ai_agent"


class CloudProvider(str, Enum):
    AZURE = "azure"
    AWS = "aws"
    GCP = "gcp"


class IdentitySource(str, Enum):
    AZURE_AD = "azure_ad"
    AWS_IAM = "aws_iam"
    GCP_IAM = "gcp_iam"


class IdentityStatus(_CaseInsensitiveMixin, str, Enum):
    ACTIVE = "Active"
    DISABLED = "Disabled"
    EXPIRED = "Expired"
    PROVISIONED = "Provisioned"


class DataMode(str, Enum):
    LIVE = "live"
    SNAPSHOT = "snapshot"


class PrivilegeLevel(str, Enum):
    HIGHLY_PRIVILEGED = "highly_privileged"
    PRIVILEGED = "privileged"
    STANDARD = "standard"


class ScopeBreadth(str, Enum):
    TENANT_WIDE = "tenant_wide"
    SUBSCRIPTION = "subscription"
    RESOURCE_GROUP = "resource_group"
    RESOURCE = "resource"


class RiskLabel(_CaseInsensitiveMixin, str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFERRED = "inferred"
    NONE = "none"


#: Canonical confidence ordering. Import from here — never redefine locally.
#: Higher rank = more trustworthy signal.
#: Used by: ConfidencePropagator, ActivitySignalsBuilder, GraphTraversalEngine,
#:          RiskEngine, AttackPathEngine.
CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.NONE:     0,
    Confidence.INFERRED: 1,
    Confidence.LOW:      2,
    Confidence.MEDIUM:   3,
    Confidence.HIGH:     4,
}


class BuilderDataSource(str, Enum):
    """E2 — Per-builder partial-data state marker.

    Every B-block carries a ``data_source`` field of this type so the
    caller can distinguish "we looked and saw nothing" (``NONE``) from
    "we observed a full row and believe it" (``FULL``) from "we saw
    an older row than our staleness threshold" (``STALE``).

    State meanings (see ``docs/backend/BUILDER_STATE_MATRIX.md``):

    * ``NONE``    — skeleton table has **zero rows** for this identity.
                    Every null field in the returned block is an honest
                    "we don't know", not a default. Confidence is NONE.
    * ``PARTIAL`` — some rows or fields exist but the builder could not
                    compute a high-confidence result (e.g. ownership row
                    present but owner_type missing). Confidence is LOW.
    * ``FULL``    — every required input field is populated and the row
                    is within the builder's freshness window. Confidence
                    is HIGH (or block-specific).
    * ``STALE``   — a row exists but its ``updated_at`` is older than
                    the builder's staleness threshold (default 24h).
                    The data is returned as-is so the UI can show it
                    with a "stale" badge instead of a blank panel.
    """

    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"
    STALE = "stale"


#: Staleness threshold applied by builders that support per-row freshness
#: tracking (i.e. skeleton tables with an ``updated_at`` column). Rows
#: older than this wall-clock age are emitted with ``data_source=STALE``
#: rather than ``FULL``. Kept here — not on individual builders — so the
#: full B-block surface can be audited from a single source of truth.
BUILDER_STALENESS_HOURS: int = 24


class OwnerQuality(str, Enum):
    ACTIVE_OWNER = "active_owner"
    INACTIVE_OWNER = "inactive_owner"
    NO_OWNER = "no_owner"


class GovernanceClassification(_CaseInsensitiveMixin, str, Enum):
    GOVERNED = "Governed"
    UNGOVERNED = "Ungoverned"
    ORPHANED = "Orphaned"
    POLICY_VIOLATION = "PolicyViolation"

    @classmethod
    def _missing_(cls, value: object) -> "Enum | None":
        if not isinstance(value, str):
            return None
        # Handle underscore variant: "policy_violation" → "PolicyViolation"
        normalised = value.replace("_", "").lower()
        for member in cls:
            if member.value.replace("_", "").lower() == normalised:
                return member
        return None


class LifecycleState(_CaseInsensitiveMixin, str, Enum):
    ACTIVE = "Active"
    DORMANT = "Dormant"
    PROVISIONED = "Provisioned"
    DISABLED = "Disabled"
    EXPIRED = "Expired"


class RoleSource(str, Enum):
    AZURE_RBAC = "azure_rbac"
    AWS_IAM = "aws_iam"
    AWS_SCP = "aws_scp"
    GCP_IAM = "gcp_iam"
    GCP_ORG_POLICY = "gcp_org_policy"


class ResourceType(str, Enum):
    KEY_VAULT = "key_vault"
    STORAGE = "storage"
    DATABASE = "database"
    SECRET = "secret"
    IAM_SYSTEM = "iam_system"
    CERTIFICATE_STORE = "certificate_store"


class SensitivityLevel(_CaseInsensitiveMixin, str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class RotationStatus(str, Enum):
    CURRENT = "current"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    NO_CREDENTIALS = "no_credentials"


# ---------------------------------------------------------------------------
# DataContext (dataclass — F3 provenance carrier)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DataContext:
    """
    Provenance for any identity-centric payload.

    Tells the consumer:
      * whether this view came from a live query or a stored snapshot,
      * which snapshot it came from (if any),
      * when the data was computed,
      * whether it has aged past its freshness threshold.
    """

    data_mode: DataMode
    snapshot_id: Optional[int] = None
    snapshot_date: Optional[datetime] = None
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    is_stale: bool = False

    def __post_init__(self) -> None:
        if self.data_mode == DataMode.SNAPSHOT and self.snapshot_id is None:
            raise ValueError(
                "DataContext: snapshot_id is required when data_mode == 'snapshot'"
            )


# ---------------------------------------------------------------------------
# Mixins / shared validators
# ---------------------------------------------------------------------------


class _OrgScoped(BaseModel):
    """Base class enforcing tenant-scoping invariant on every model."""

    organization_id: str = Field(
        ...,
        description="Owning organization (tenant) identifier. Mandatory for RLS.",
    )

    @field_validator("organization_id")
    @classmethod
    def _organization_id_not_empty(cls, value: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("organization_id must be a non-empty string")
        return value


# ---------------------------------------------------------------------------
# Resource (typed target for attack paths and access edges)
# ---------------------------------------------------------------------------


class Resource(_OrgScoped):
    """A cloud resource that can be targeted by an identity or attack path."""

    id: str = Field(..., description="Provider-native resource identifier (e.g. ARM id)")
    global_identity_id: uuid.UUID = Field(
        ..., description="Stable cross-cloud UUID for this resource"
    )
    cloud_id: CloudProvider
    type: ResourceType
    name: str
    sensitivity: SensitivityLevel


# ---------------------------------------------------------------------------
# Roles (usage embedded — never a side dict)
# ---------------------------------------------------------------------------


class RoleUsage(_OrgScoped):
    """Per-assignment usage signal — embedded inside RoleAssignment."""

    used: bool
    confidence: Confidence
    evidence: str


class RoleAssignment(_OrgScoped):
    """A single role assignment with embedded usage telemetry."""

    role_name: str
    role_key: str
    scope: str
    scope_level: ScopeBreadth
    source: RoleSource
    usage: RoleUsage

    @field_validator("role_key")
    @classmethod
    def _role_key_lowercase(cls, value: str) -> str:
        if value != value.lower():
            raise ValueError("role_key must be lowercase")
        return value


# ---------------------------------------------------------------------------
# Risk + attack path primitives
# ---------------------------------------------------------------------------


class RiskFactor(_OrgScoped):
    """One contributing dimension to an identity's overall risk score."""

    dimension: str
    label: str
    contribution: float
    severity: RiskLabel


class AttackChainStep(_OrgScoped):
    """A single step in an attack chain narrative."""

    step: str


class AttackPath(_OrgScoped):
    """An end-to-end attack path from a source identity to a typed Resource."""

    path_id: str
    path_type: str
    source_identity_id: uuid.UUID
    target: Resource
    severity: RiskLabel
    score: float = Field(..., ge=0.0, le=100.0)
    chain: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Remediation + ownership primitives
# ---------------------------------------------------------------------------


class RemediationAction(_OrgScoped):
    """A single recommended remediation action."""

    priority: int
    description: str
    auto_fixable: bool
    fix_command: Optional[str] = Field(
        default=None,
        description=(
            "null when ``auto_fixable`` is False — manual actions have "
            "no shell command to run."
        ),
    )


class IdentityOwner(_OrgScoped):
    """Owner / accountable principal for an identity."""

    id: str
    name: str
    type: str
    last_active_days: Optional[int] = Field(
        default=None,
        description=(
            "null when the owner has no observable activity record "
            "(e.g. a service account never queried for sign-ins)."
        ),
    )
    has_reviewed: bool


# ---------------------------------------------------------------------------
# B01 — IdentityProfile (with F1 + F3 patches)
# ---------------------------------------------------------------------------


class IdentityProfile(_OrgScoped):
    """
    B01 — Core identity profile.

    Carries the F1 stable cross-cloud UUID (`global_identity_id`),
    the federation linkage fields (`is_federated_identity`, `federated_from`),
    and the F3 `data_context` provenance carrier.
    """

    # Stable cross-cloud identifier (F1)
    global_identity_id: uuid.UUID

    # Provider-native identifiers
    identity_id: str
    object_id: Optional[str] = Field(
        default=None,
        description=(
            "null for identities whose provider does not emit an "
            "object_id separate from identity_id (e.g. AWS IAM principals)."
        ),
    )
    display_name: str
    user_principal_name: Optional[str] = Field(
        default=None,
        description=(
            "null for non-human identities (service principals, managed "
            "identities, AI agents) that do not have a UPN."
        ),
    )

    # Classification
    identity_type: IdentityType
    cloud_id: CloudProvider
    source: IdentitySource
    status: IdentityStatus

    # Federation linkage
    is_federated_identity: bool = False
    federated_from: Optional[uuid.UUID] = Field(
        default=None,
        description=(
            "null unless ``is_federated_identity`` is True. When set, "
            "points at the upstream identity's ``global_identity_id``."
        ),
    )

    # Lifecycle metadata
    created_at: Optional[datetime] = Field(
        default=None,
        description=(
            "null when the provider did not surface a creation timestamp "
            "(older AWS IAM users, some GCP service accounts)."
        ),
    )
    last_modified_at: Optional[datetime] = Field(
        default=None,
        description=(
            "null when the provider does not track modification history "
            "for this identity type."
        ),
    )
    discovered_at: Optional[datetime] = Field(
        default=None,
        description=(
            "null when the identity was loaded from a snapshot that "
            "pre-dates the discovery-timestamp column."
        ),
    )

    # F3 — provenance carrier
    data_context: DataContext

    model_config = {"arbitrary_types_allowed": True}


# ---------------------------------------------------------------------------
# B02 — Activity
# ---------------------------------------------------------------------------


class ActivityState(_OrgScoped):
    """B02 — Activity / lifecycle state of an identity.

    Produced by :class:`ActivityBuilder`. When the skeleton table
    ``identity_activity`` has no row for this identity the builder returns
    ``lifecycle_state=PROVISIONED``, ``activity_confidence=NONE``, and
    ``data_source=BuilderDataSource.NONE`` — consumers MUST treat the
    enum defaults as placeholders in that case. See E2 state matrix in
    ``docs/backend/BUILDER_STATE_MATRIX.md``.
    """

    lifecycle_state: LifecycleState
    last_sign_in_at: Optional[datetime] = Field(
        default=None,
        description=(
            "null when data_source == 'none' or no sign-in has been "
            "observed yet. Never null when data_source == 'full'."
        ),
    )
    last_activity_at: Optional[datetime] = Field(
        default=None,
        description=(
            "null when data_source == 'none' or no activity has been "
            "observed yet. Never null when data_source == 'full'."
        ),
    )
    days_since_last_activity: Optional[int] = Field(
        default=None,
        description="null iff ``last_activity_at`` is null.",
    )
    activity_confidence: Confidence
    is_dormant: bool = False
    has_p2_telemetry: bool = False
    data_source: BuilderDataSource = Field(
        default=BuilderDataSource.FULL,
        description=(
            "E2 partial-data state. ``NONE`` when the ``identity_activity`` "
            "row is missing; ``STALE`` when its ``updated_at`` is older than "
            "``BUILDER_STALENESS_HOURS``; ``PARTIAL`` when a row exists but "
            "required fields (e.g. ``last_sign_in_at``) are unpopulated."
        ),
    )
    missing_signals: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered list of dotted field paths the builder could not "
            "populate (e.g. ``['last_sign_in_at', 'last_activity_at']``). "
            "Empty when ``data_source == 'full'``."
        ),
    )


# ---------------------------------------------------------------------------
# B03 — Ownership
# ---------------------------------------------------------------------------


class OwnershipBlock(_OrgScoped):
    """B03 — Ownership accountability for an identity.

    Produced by :class:`OwnershipBuilder`. When the skeleton table
    ``identity_owners`` has no row for this identity the builder returns
    ``owner_quality=NO_OWNER`` with an empty ``owners`` list — this is
    the canonical null-state representation and ``data_source`` is
    stamped ``NONE``.
    """

    owner_quality: OwnerQuality
    owners: list[IdentityOwner] = Field(default_factory=list)
    last_review_at: Optional[datetime] = Field(
        default=None,
        description=(
            "null when no attestation has ever been recorded, or when "
            "data_source == 'none'."
        ),
    )
    days_since_last_review: Optional[int] = Field(
        default=None,
        description="null iff ``last_review_at`` is null.",
    )
    requires_attestation: bool = False
    confidence: Confidence = Field(
        default=Confidence.NONE,
        description=(
            "High when an owner row with a known owner_type was observed; "
            "Low when a row exists but owner_type was inferred; None when "
            "data_source == 'none'."
        ),
    )
    data_source: BuilderDataSource = Field(
        default=BuilderDataSource.FULL,
        description=(
            "E2 partial-data state. ``NONE`` when ``identity_owners`` has "
            "no row; ``PARTIAL`` when a row exists but required fields are "
            "null (e.g. ``owner_type``). ``STALE`` is not produced by this "
            "builder — ``identity_owners`` has no ``updated_at`` column."
        ),
    )
    missing_signals: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered list of dotted field paths the builder could not "
            "populate. Empty when ``data_source == 'full'``."
        ),
    )


# ---------------------------------------------------------------------------
# B04 — Governance
# ---------------------------------------------------------------------------


class GovernanceBlock(_OrgScoped):
    """B04 — Governance posture and policy compliance.

    Produced by :class:`GovernanceEngine.derive` — a *pure* function of
    the upstream ``ActivityState`` and ``OwnershipBlock`` blocks. If both
    upstream blocks carry ``data_source == NONE`` then this block will
    too: governance cannot be inferred from nothing.
    """

    classification: GovernanceClassification
    is_governed: bool
    policy_violations: list[str] = Field(default_factory=list)
    has_lifecycle_policy: bool = False
    has_access_review: bool = False
    governance_confidence: Confidence
    data_source: BuilderDataSource = Field(
        default=BuilderDataSource.FULL,
        description=(
            "E2 partial-data state. Derived from upstream blocks: "
            "``NONE`` when both activity and ownership have data_source "
            "NONE; ``PARTIAL`` when at least one is NONE or PARTIAL; "
            "``FULL`` only when both upstreams are FULL."
        ),
    )
    missing_signals: list[str] = Field(
        default_factory=list,
        description=(
            "Names of upstream signals this engine could not consume "
            "(e.g. ``['activity', 'ownership']``). Empty when FULL."
        ),
    )


# ---------------------------------------------------------------------------
# B05 — Privilege
# ---------------------------------------------------------------------------


class PrivilegeBlock(_OrgScoped):
    """B05 — Privilege footprint summary.

    Produced by :class:`PrivilegeBuilder`. When the skeleton table
    ``identity_privilege_summary`` has no row for this identity the
    builder returns ``privilege_level=STANDARD``, ``scope_breadth=RESOURCE``,
    and ``data_source=BuilderDataSource.NONE`` — consumers MUST treat the
    enum defaults as placeholders in that case.
    """

    privilege_level: PrivilegeLevel
    scope_breadth: ScopeBreadth
    highly_privileged_role_count: int = 0
    privileged_role_count: int = 0
    standard_role_count: int = 0
    total_role_count: int = 0
    can_escalate: bool = False
    blast_radius_resource_count: int = 0
    confidence: Confidence = Field(
        default=Confidence.NONE,
        description=(
            "High when the row was computed from a full role assignment "
            "inventory; Low when inferred from a partial role count; "
            "None when data_source == 'none'."
        ),
    )
    data_source: BuilderDataSource = Field(
        default=BuilderDataSource.FULL,
        description=(
            "E2 partial-data state. ``NONE`` when "
            "``identity_privilege_summary`` has no row; ``PARTIAL`` when "
            "total_role_count > 0 but privilege_level could not be "
            "determined. ``STALE`` is not produced by this builder — "
            "the skeleton table has no ``updated_at`` column."
        ),
    )
    missing_signals: list[str] = Field(
        default_factory=list,
        description=(
            "Ordered list of dotted field paths the builder could not "
            "populate. Empty when ``data_source == 'full'``."
        ),
    )


# ---------------------------------------------------------------------------
# B06 — Risk score
# ---------------------------------------------------------------------------


class RiskScoreBlock(_OrgScoped):
    """B06 — Aggregated risk score and contributing factors."""

    score: float = Field(..., ge=0.0, le=100.0)
    label: RiskLabel
    factors: list[RiskFactor] = Field(default_factory=list)
    computed_at: datetime
    model_version: str

    model_config = {"protected_namespaces": ()}


# ---------------------------------------------------------------------------
# B07 — Roles
# ---------------------------------------------------------------------------


class RolesBlock(_OrgScoped):
    """B07 — All role assignments held by the identity (usage embedded)."""

    roles: list[RoleAssignment] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# B08 — Attack paths
# ---------------------------------------------------------------------------


class AttackPathsBlock(_OrgScoped):
    """B08 — Discovered attack paths originating from this identity."""

    paths: list[AttackPath] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Blast radius — aggregate reachability (Phase 3)
# ---------------------------------------------------------------------------


class BlastRadiusResult(_OrgScoped):
    """Aggregate reachability result for a single identity.

    Produced by IdentityBlastRadiusEngine. Distinct from
    AttackPathsBlock (which lists concrete attack chains).
    The three bucket lists are disjoint — every resource appears
    in exactly one bucket. Low/Info resources are counted in
    total_reachable but not listed (they dominate payload size).

    When the graph has no traversable edges from this identity the
    engine returns an empty result with ``total_reachable=0`` and
    ``data_source=BuilderDataSource.NONE`` — consumers MUST treat
    zeros as placeholders in that case rather than a real "this
    identity has no blast radius" finding.
    """

    model_config = ConfigDict(frozen=True)

    identity_id: str = Field(..., description="Provider-native identity id")
    critical_resources: list[Resource] = Field(default_factory=list)
    high_resources: list[Resource] = Field(default_factory=list)
    medium_resources: list[Resource] = Field(default_factory=list)
    #: Total distinct reachable resources across ALL sensitivity tiers.
    total_reachable: int = Field(default=0, ge=0)
    #: Histogram: first-edge-type → count of resources reachable via that edge.
    #: A resource reachable via both HAS_ROLE and MEMBER_OF counts once in each.
    reachable_by_path_type: dict[str, int] = Field(default_factory=dict)
    traversal_depth: int = Field(default=0, ge=0)
    policy_name: str = ""
    truncated: bool = False
    data_source: BuilderDataSource = Field(
        default=BuilderDataSource.FULL,
        description=(
            "E2 partial-data state. ``NONE`` when the identity has no "
            "outbound edges in the access graph (zero reachable resources); "
            "``PARTIAL`` when traversal was truncated before exhausting "
            "frontier; ``FULL`` otherwise."
        ),
    )
    missing_signals: list[str] = Field(
        default_factory=list,
        description=(
            "Reasons the traversal produced a degraded result, e.g. "
            "``['graph_edges']`` (identity absent from graph) or "
            "``['truncated_frontier']`` (policy cap hit)."
        ),
    )


# ---------------------------------------------------------------------------
# B09 — Remediation
# ---------------------------------------------------------------------------


class RemediationBlock(_OrgScoped):
    """B09 — Remediation actions bucketed by priority."""

    p0_count: int = 0
    p1_count: int = 0
    p2_count: int = 0
    actions: list[RemediationAction] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# IdentityState — composite of all B-blocks
# ---------------------------------------------------------------------------


class IdentityState(_OrgScoped):
    """
    Composite identity state assembled from blocks B01-B09.

    The `data_context` field is the authoritative provenance for the entire
    state object — every consumer should propagate it onto downstream views.
    """

    profile: IdentityProfile
    activity: ActivityState
    ownership: OwnershipBlock
    governance: GovernanceBlock
    privilege: PrivilegeBlock
    risk: RiskScoreBlock
    roles: RolesBlock
    attack_paths: AttackPathsBlock
    blast_radius: Optional[BlastRadiusResult] = Field(
        default=None,
        description=(
            "null when the Phase 3 blast-radius feature flag is off, "
            "or when the traversal engine raised and degraded to None. "
            "NEVER null to indicate 'no reachable resources' — that is "
            "represented as a populated result with ``total_reachable=0`` "
            "and ``data_source=BuilderDataSource.NONE``."
        ),
    )
    remediation: RemediationBlock
    data_context: DataContext

    model_config = {"arbitrary_types_allowed": True}
