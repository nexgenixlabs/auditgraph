/**
 * AuditGraph — Identity module canonical type contract.
 *
 * Mirrors `backend/app/schemas/identity.py` (Pydantic v2) one-to-one.
 * Every Python enum is expressed as a TypeScript string literal union,
 * and every Pydantic model has a matching interface below.
 *
 * Invariants (kept in lock-step with the backend):
 *  - `organization_id: string` is MANDATORY on every object — never optional.
 *  - `global_identity_id` is the stable cross-cloud UUID (serialized as string).
 *  - `RoleAssignment.usage` is EMBEDDED — never a side dict keyed elsewhere.
 *  - `AttackPath.target` is a typed `Resource` — never a raw string path.
 *  - `DataContext` is propagated onto every identity payload and indicates
 *    whether the data is live, stale, or drawn from a snapshot.
 */

// ---------------------------------------------------------------------------
// Enums (string literal unions)
// ---------------------------------------------------------------------------

/** Logical identity type, cross-cloud. */
export type IdentityType =
  | 'human_user'
  | 'guest_user'
  | 'service_principal'
  | 'managed_identity'
  | 'app_registration'
  | 'ai_agent';

/** Cloud provider the identity lives in. */
export type CloudProvider = 'azure' | 'aws' | 'gcp';

/** Upstream directory / IAM source. */
export type IdentitySource = 'azure_ad' | 'aws_iam' | 'gcp_iam';

/** Provisioning / enablement status. */
export type IdentityStatus = 'Active' | 'Disabled' | 'Expired' | 'Provisioned';

/** Data provenance mode for a payload. */
export type DataMode = 'live' | 'snapshot';

/** Privilege tier used by the risk engine. */
export type PrivilegeLevel = 'highly_privileged' | 'privileged' | 'standard';

/** Maximum scope breadth granted to the identity. */
export type ScopeBreadth = 'tenant_wide' | 'subscription' | 'resource_group' | 'resource';

/** Canonical risk label bucket. */
export type RiskLabel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

/** Confidence level for inferred signals (activity, usage, etc.). */
export type Confidence = 'high' | 'medium' | 'low' | 'inferred' | 'none';

/** Quality of ownership for an identity. */
export type OwnerQuality = 'active_owner' | 'inactive_owner' | 'no_owner';

/** Governance classification derived from ownership + activity + policy. */
export type GovernanceClassification =
  | 'Governed'
  | 'Ungoverned'
  | 'Orphaned'
  | 'PolicyViolation';

/** Lifecycle state of the identity. */
export type LifecycleState = 'Active' | 'Dormant' | 'Provisioned' | 'Disabled' | 'Expired';

/** Source system for a role assignment. */
export type RoleSource =
  | 'azure_rbac'
  | 'aws_iam'
  | 'aws_scp'
  | 'gcp_iam'
  | 'gcp_org_policy';

/** Typed cloud resource categories (attack-path targets). */
export type ResourceType =
  | 'key_vault'
  | 'storage'
  | 'database'
  | 'secret'
  | 'iam_system'
  | 'certificate_store';

/** Data sensitivity classification for a resource. */
export type SensitivityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

/** Credential rotation status. */
export type RotationStatus = 'current' | 'expiring_soon' | 'expired' | 'no_credentials';

// ---------------------------------------------------------------------------
// DataContext (provenance carrier)
// ---------------------------------------------------------------------------

/**
 * Provenance and freshness metadata for an identity payload.
 *
 * - `data_mode === 'snapshot'` implies `snapshot_id` is set.
 * - `is_stale` is true only for live payloads that have aged past the
 *   backend freshness threshold.
 */
export interface DataContext {
  data_mode: DataMode;
  snapshot_id: number | null;
  snapshot_date: string | null;
  computed_at: string;
  is_stale: boolean;
}

// ---------------------------------------------------------------------------
// Resource (typed attack-path target)
// ---------------------------------------------------------------------------

/**
 * A cloud resource that can be targeted by an identity or an attack path.
 * `global_identity_id` is the stable cross-cloud UUID (nullable on the wire
 * if the resource has not yet been correlated).
 */
export interface Resource {
  id: number;
  global_identity_id: string | null;
  cloud_id: string;
  type: ResourceType;
  name: string;
  sensitivity: SensitivityLevel;
  organization_id: string;
}

// ---------------------------------------------------------------------------
// Role primitives — usage is embedded on the assignment
// ---------------------------------------------------------------------------

/**
 * Per-assignment usage telemetry. Always embedded on `RoleAssignment`;
 * never returned in a separate keyed dictionary.
 */
export interface RoleUsage {
  used: boolean;
  confidence: Confidence;
  evidence: string;
  organization_id: string;
}

/**
 * A single role assignment. `role_key` is always lowercase to match the
 * backend validator. `usage` is embedded.
 */
export interface RoleAssignment {
  role_name: string;
  role_key: string;
  scope: string;
  scope_level: ScopeBreadth;
  source: RoleSource;
  usage: RoleUsage;
  organization_id: string;
}

// ---------------------------------------------------------------------------
// Risk / attack-path primitives
// ---------------------------------------------------------------------------

/** One contributing dimension to an identity's overall risk score. */
export interface RiskFactor {
  dimension: string;
  label: string;
  contribution: number;
  severity: RiskLabel;
  organization_id: string;
}

/**
 * An end-to-end attack path rooted at an identity. The `target` is a
 * typed `Resource` — never a string path — and `score` is in [0, 100].
 */
export interface AttackPath {
  path_id: string;
  path_type: string;
  source_identity_id: string;
  target: Resource;
  severity: RiskLabel;
  score: number;
  chain: string[];
  mitre_techniques: string[];
  organization_id: string;
}

// ---------------------------------------------------------------------------
// Remediation + ownership primitives
// ---------------------------------------------------------------------------

/** A single recommended remediation action. */
export interface RemediationAction {
  priority: number;
  description: string;
  auto_fixable: boolean;
  fix_command: string | null;
  organization_id: string;
}

/** Owner / accountable principal for an identity. */
export interface IdentityOwner {
  id: string;
  name: string;
  type: string;
  last_active_days: number | null;
  has_reviewed: boolean;
  organization_id: string;
}

// ---------------------------------------------------------------------------
// B01 — IdentityProfile
// ---------------------------------------------------------------------------

/**
 * B01 — Core identity profile.
 *
 * Carries the stable cross-cloud UUID (`global_identity_id`), the federation
 * linkage fields (`is_federated_identity`, `federated_from`), and the
 * `data_context` provenance carrier.
 */
export interface IdentityProfile {
  global_identity_id: string;
  identity_id: string;
  object_id: string | null;
  display_name: string;
  user_principal_name: string | null;
  identity_type: IdentityType;
  cloud_id: CloudProvider;
  source: IdentitySource;
  status: IdentityStatus;
  is_federated_identity: boolean;
  federated_from: string | null;
  created_at: string | null;
  last_modified_at: string | null;
  discovered_at: string | null;
  data_context: DataContext;
  organization_id: string;
}

// ---------------------------------------------------------------------------
// B02 — ActivityState
// ---------------------------------------------------------------------------

/** B02 — Activity / lifecycle posture for the identity. */
export interface ActivityState {
  lifecycle_state: LifecycleState;
  last_sign_in_at: string | null;
  last_activity_at: string | null;
  days_since_last_activity: number | null;
  activity_confidence: Confidence;
  is_dormant: boolean;
  has_p2_telemetry: boolean;
  organization_id: string;
}

// ---------------------------------------------------------------------------
// B03 — OwnershipBlock
// ---------------------------------------------------------------------------

/** B03 — Ownership accountability for the identity. */
export interface OwnershipBlock {
  owner_quality: OwnerQuality;
  owners: IdentityOwner[];
  last_review_at: string | null;
  days_since_last_review: number | null;
  requires_attestation: boolean;
  organization_id: string;
}

// ---------------------------------------------------------------------------
// B04 — GovernanceBlock
// ---------------------------------------------------------------------------

/** B04 — Governance posture and policy compliance. */
export interface GovernanceBlock {
  classification: GovernanceClassification;
  is_governed: boolean;
  policy_violations: string[];
  has_lifecycle_policy: boolean;
  has_access_review: boolean;
  governance_confidence: Confidence;
  organization_id: string;
}

// ---------------------------------------------------------------------------
// B05 — PrivilegeBlock
// ---------------------------------------------------------------------------

/** B05 — Privilege footprint summary. */
export interface PrivilegeBlock {
  privilege_level: PrivilegeLevel;
  scope_breadth: ScopeBreadth;
  highly_privileged_role_count: number;
  privileged_role_count: number;
  standard_role_count: number;
  total_role_count: number;
  can_escalate: boolean;
  blast_radius_resource_count: number;
  organization_id: string;
}

// ---------------------------------------------------------------------------
// B06 — RiskScoreBlock
// ---------------------------------------------------------------------------

/**
 * B06 — Aggregated risk score and contributing factors.
 * `score` is normalized to the 0–100 range.
 */
export interface RiskScoreBlock {
  score: number;
  label: RiskLabel;
  factors: RiskFactor[];
  computed_at: string;
  model_version: string;
  organization_id: string;
}

// ---------------------------------------------------------------------------
// B07 — RolesBlock
// ---------------------------------------------------------------------------

/** B07 — All role assignments held by the identity (usage embedded). */
export interface RolesBlock {
  roles: RoleAssignment[];
  organization_id: string;
}

// ---------------------------------------------------------------------------
// B08 — AttackPathsBlock
// ---------------------------------------------------------------------------

/** B08 — Discovered attack paths originating from this identity. */
export interface AttackPathsBlock {
  paths: AttackPath[];
  organization_id: string;
}

// ---------------------------------------------------------------------------
// B09 — RemediationBlock
// ---------------------------------------------------------------------------

/** B09 — Remediation actions bucketed by priority. */
export interface RemediationBlock {
  p0_count: number;
  p1_count: number;
  p2_count: number;
  actions: RemediationAction[];
  organization_id: string;
}

// ---------------------------------------------------------------------------
// IdentityState — composite of all B-blocks
// ---------------------------------------------------------------------------

/**
 * Composite identity state assembled from blocks B01–B09. The top-level
 * `data_context` is the authoritative provenance for the entire payload.
 */
export interface IdentityState {
  organization_id: string;
  profile: IdentityProfile;
  activity: ActivityState;
  ownership: OwnershipBlock;
  governance: GovernanceBlock;
  privilege: PrivilegeBlock;
  risk_score: RiskScoreBlock;
  roles: RolesBlock;
  attack_paths: AttackPathsBlock;
  remediation: RemediationBlock;
  data_context: DataContext;
}

// ---------------------------------------------------------------------------
// IdentityListRow — flattened row for list / table views
// ---------------------------------------------------------------------------

/**
 * Flattened identity row used by list / table views. Carries its own
 * `data_context` so the UI can badge stale or snapshot-sourced rows.
 */
export interface IdentityListRow {
  identity_id: string;
  global_identity_id: string;
  organization_id: string;
  display_name: string;
  identity_type: IdentityType;
  cloud_provider: CloudProvider;
  risk_label: RiskLabel;
  risk_score: number;
  governance: GovernanceClassification;
  lifecycle_state: LifecycleState;
  is_dormant: boolean;
  privilege_level: PrivilegeLevel;
  last_seen: string | null;
  data_context: DataContext;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Type guard: true when the payload was drawn from a point-in-time
 * snapshot rather than a live query.
 */
export function isSnapshotMode(ctx: DataContext): boolean {
  return ctx.data_mode === 'snapshot';
}
