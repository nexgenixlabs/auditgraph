/**
 * Identity Engine v1 API Client
 *
 * Typed client for the Phase 3 identity engine endpoints.
 * Uses the shared apiClient (which inherits the global Bearer token).
 */

import api from './apiClient';

// ── Enums ────────────────────────────────────────────────────────────

export type IdentityType =
  | 'human_user' | 'guest_user' | 'service_principal'
  | 'managed_identity' | 'app_registration' | 'ai_agent';

export type CloudProvider = 'azure' | 'aws' | 'gcp';
export type RiskLabel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type GovernanceClassification = 'Governed' | 'Ungoverned' | 'Orphaned' | 'PolicyViolation';
export type LifecycleState = 'Active' | 'Dormant' | 'Provisioned' | 'Disabled' | 'Expired';
export type PrivilegeLevel = 'highly_privileged' | 'privileged' | 'standard';
export type Confidence = 'high' | 'medium' | 'low' | 'inferred' | 'none';
export type BuilderDataSource = 'none' | 'partial' | 'full' | 'stale';
export type DataMode = 'live' | 'snapshot';
export type ScopeBreadth = 'tenant_wide' | 'subscription' | 'resource_group' | 'resource';
export type SimulationType = 'ROLE_REMOVAL' | 'PRIVILEGE_REDUCTION' | 'OWNERSHIP_ASSIGNMENT';

// ── DTOs ─────────────────────────────────────────────────────────────

export interface DataContextDTO {
  data_mode: DataMode;
  snapshot_id?: number | null;
  snapshot_date?: string | null;
  computed_at: string;
  is_stale: boolean;
}

export interface IdentityListRow {
  identity_id: string;
  global_identity_id: string;
  organization_id: string;
  display_name: string;
  identity_type: IdentityType;
  cloud_provider: CloudProvider;
  risk_label: RiskLabel;
  /** Proprietary score — internal only, do NOT render. Use risk_score_cvss. */
  risk_score: number;
  /** CVSS-aligned 0-10 (industry standard, FIRST.org). Render this. */
  risk_score_cvss?: number;
  governance: GovernanceClassification;
  lifecycle_state: LifecycleState;
  is_dormant: boolean;
  privilege_level: PrivilegeLevel;
  last_seen: string | null;
  data_context: DataContextDTO;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  offset: number;
  limit: number;
  data_context: DataContextDTO;
}

// ── Identity State (Detail) ──────────────────────────────────────────

export interface IdentityProfile {
  organization_id: string;
  global_identity_id: string;
  identity_id: string;
  object_id?: string | null;
  display_name: string;
  user_principal_name?: string | null;
  identity_type: IdentityType;
  cloud_id: CloudProvider;
  source: string;
  status: string;
  is_federated_identity: boolean;
  federated_from?: string | null;
  created_at?: string | null;
  last_modified_at?: string | null;
  discovered_at?: string | null;
  data_context: DataContextDTO;
}

export interface ActivityState {
  organization_id: string;
  lifecycle_state: LifecycleState;
  last_sign_in_at?: string | null;
  last_activity_at?: string | null;
  days_since_last_activity?: number | null;
  activity_confidence: Confidence;
  is_dormant: boolean;
  has_p2_telemetry: boolean;
  data_source: BuilderDataSource;
  missing_signals: string[];
}

export interface IdentityOwner {
  id: string;
  name: string;
  type: string;
  last_active_days?: number | null;
  has_reviewed: boolean;
}

export interface OwnershipBlock {
  organization_id: string;
  owner_quality: string;
  owners: IdentityOwner[];
  last_review_at?: string | null;
  days_since_last_review?: number | null;
  requires_attestation: boolean;
  confidence: Confidence;
  data_source: BuilderDataSource;
  missing_signals: string[];
}

export interface GovernanceBlock {
  organization_id: string;
  classification: GovernanceClassification;
  is_governed: boolean;
  policy_violations: string[];
  has_lifecycle_policy: boolean;
  has_access_review: boolean;
  governance_confidence: Confidence;
  data_source: BuilderDataSource;
  missing_signals: string[];
}

export interface PrivilegeBlock {
  organization_id: string;
  privilege_level: PrivilegeLevel;
  scope_breadth: ScopeBreadth;
  highly_privileged_role_count: number;
  privileged_role_count: number;
  standard_role_count: number;
  total_role_count: number;
  can_escalate: boolean;
  blast_radius_resource_count: number;
  confidence: Confidence;
  data_source: BuilderDataSource;
  missing_signals: string[];
}

export interface RiskFactor {
  dimension: string;
  label: string;
  contribution: number;
  severity: RiskLabel;
}

export interface RiskScoreBlock {
  organization_id: string;
  score: number;
  label: RiskLabel;
  factors: RiskFactor[];
  computed_at: string;
  model_version: string;
}

export interface RoleUsage {
  used: boolean;
  confidence: Confidence;
  evidence: string;
}

export interface RoleAssignment {
  organization_id: string;
  role_name: string;
  role_key: string;
  scope: string;
  scope_level: ScopeBreadth;
  source: string;
  usage: RoleUsage;
}

export interface RolesBlock {
  organization_id: string;
  roles: RoleAssignment[];
}

export interface Resource {
  id: string;
  global_identity_id: string;
  cloud_id: CloudProvider;
  type: string;
  name: string;
  sensitivity: string;
}

export interface AttackPath {
  path_id: string;
  path_type: string;
  source_identity_id: string;
  target: Resource;
  severity: RiskLabel;
  score: number;
  chain: string[];
  mitre_techniques: string[];
}

export interface AttackPathsBlock {
  organization_id: string;
  paths: AttackPath[];
}

export interface BlastRadiusResult {
  organization_id: string;
  identity_id: string;
  critical_resources: Resource[];
  high_resources: Resource[];
  medium_resources: Resource[];
  total_reachable: number;
  reachable_by_path_type: Record<string, number>;
  traversal_depth: number;
  policy_name: string;
  truncated: boolean;
  data_source: BuilderDataSource;
  missing_signals: string[];
}

export interface RemediationAction {
  priority: number;
  description: string;
  auto_fixable: boolean;
  fix_command?: string | null;
}

export interface RemediationBlock {
  organization_id: string;
  p0_count: number;
  p1_count: number;
  p2_count: number;
  actions: RemediationAction[];
}

export interface IdentityState {
  organization_id: string;
  profile: IdentityProfile;
  activity: ActivityState;
  ownership: OwnershipBlock;
  governance: GovernanceBlock;
  privilege: PrivilegeBlock;
  risk: RiskScoreBlock;
  roles: RolesBlock;
  attack_paths: AttackPathsBlock;
  blast_radius: BlastRadiusResult | null;
  remediation: RemediationBlock;
  data_context: DataContextDTO;
}

// ── Simulations ──────────────────────────────────────────────────────

export interface WhatIfSimulationItem {
  id: string;
  organization_id: number;
  identity_id: string;
  simulation_type: SimulationType;
  input_payload: Record<string, any>;
  result_payload: Record<string, any>;
  blast_radius_before: number;
  blast_radius_after: number;
  score_delta: number;
  simulated_at: string;
  simulated_by?: number | null;
}

export interface WhatIfSimulationListResponse {
  identity_id: string;
  organization_id: number;
  total: number;
  items: WhatIfSimulationItem[];
}

export interface WhatIfSnapshot {
  risk_score: number;
  risk_label: string;
  privilege_level: string;
  governance: string;
  is_dormant: boolean;
}

export interface WhatIfResult {
  simulation_id?: string;
  identity_id: string;
  identity_display_name: string;
  simulation_type: SimulationType;
  organization_id: number;
  before: WhatIfSnapshot;
  after: WhatIfSnapshot;
  blast_radius_before: number;
  blast_radius_after: number;
  score_delta: number;
  narrative: string;
  simulated_at: string;
  engine_version: string;
}

// ── Posture DTOs ────────────────────────────────────────────────────

export interface DimensionScores {
  attack_surface: number;
  privilege: number;
  credentials: number;
  activity: number;
  governance: number;
}

export interface PostureScoreResponse {
  organization_id: number;
  score_date: string;
  overall_score: number;
  dimension_scores: DimensionScores;
  identity_count: number;
  governed_count: number;
  orphaned_count: number;
  stale_count: number;
  at_risk_count: number;
  computed_by: string;
  data_freshness: 'live' | 'stale';
}

export interface PostureScoreHistoryRow {
  score_date: string;
  overall_score: number;
  dimension_scores: DimensionScores;
  identity_count: number;
  at_risk_count: number;
}

export interface PostureScoreHistoryResponse {
  organization_id: number;
  days: number;
  engine_version: string;
  items: PostureScoreHistoryRow[];
}

export interface PriorityActionItem {
  action_type: string;
  description: string;
  affected_identity_count: number;
  estimated_score_impact: number;
  identity_filter: string;
}

export interface PriorityActionsResponse {
  organization_id: number;
  actions: PriorityActionItem[];
}

// ── API Functions ────────────────────────────────────────────────────

const V1 = '/api/v1/identities';
const POSTURE = '/api/v1/posture';

export interface ListIdentitiesParams {
  limit?: number;
  offset?: number;
  identity_type?: IdentityType;
  risk_label?: RiskLabel;
  is_dormant?: boolean;
  cloud_provider?: CloudProvider;
  snapshot_id?: number;
}

export async function listIdentities(
  params: ListIdentitiesParams = {},
): Promise<PaginatedResponse<IdentityListRow>> {
  const qs = new URLSearchParams();
  if (params.limit != null) qs.set('limit', String(params.limit));
  if (params.offset != null) qs.set('offset', String(params.offset));
  if (params.identity_type) qs.set('identity_type', params.identity_type);
  if (params.risk_label) qs.set('risk_label', params.risk_label);
  if (params.is_dormant != null) qs.set('is_dormant', String(params.is_dormant));
  if (params.cloud_provider) qs.set('cloud_provider', params.cloud_provider);
  if (params.snapshot_id != null) qs.set('snapshot_id', String(params.snapshot_id));
  const q = qs.toString();
  return api.get<PaginatedResponse<IdentityListRow>>(`${V1}${q ? `?${q}` : ''}`);
}

export async function getIdentityState(identityId: string): Promise<IdentityState> {
  return api.get<IdentityState>(`${V1}/${encodeURIComponent(identityId)}`);
}

export async function getIdentitySimulations(
  identityId: string,
): Promise<WhatIfSimulationListResponse> {
  return api.get<WhatIfSimulationListResponse>(
    `${V1}/${encodeURIComponent(identityId)}/simulations`,
  );
}

export async function runSimulation(
  identityId: string,
  simulationType: SimulationType,
  payload: Record<string, any> = {},
): Promise<WhatIfResult> {
  return api.post<WhatIfResult>(
    `${V1}/${encodeURIComponent(identityId)}/simulate`,
    { simulation_type: simulationType, payload },
  );
}

// ── Posture API ─────────────────────────────────────────────────────

export async function getPostureScore(): Promise<PostureScoreResponse> {
  return api.get<PostureScoreResponse>(`${POSTURE}/score`);
}

export async function getPostureHistory(
  days: number = 30,
): Promise<PostureScoreHistoryResponse> {
  return api.get<PostureScoreHistoryResponse>(`${POSTURE}/score/history?days=${days}`);
}

export async function recomputePostureScore(): Promise<PostureScoreResponse> {
  return api.post<PostureScoreResponse>(`${POSTURE}/score/recompute`);
}

export async function getPostureActions(): Promise<PriorityActionsResponse> {
  return api.get<PriorityActionsResponse>(`${POSTURE}/actions`);
}

// ── Simulation Export ───────────────────────────────────────────────

export interface SimulationFindingArtifact {
  finding_type: string;
  generated_at: string;
  generated_by: string;
  organization_id: number;
  identity: { id: string; name: string; type: string };
  simulation: {
    type: string;
    input: Record<string, any>;
    result: {
      score_before: number;
      score_after: number;
      delta: number;
      blast_radius_before: number;
      blast_radius_after: number;
      confidence: 'HIGH' | 'MEDIUM' | 'LOW';
    };
  };
  recommendation: string;
  evidence_references: string[];
}

export async function exportSimulation(
  identityId: string,
  simulationId: string,
): Promise<SimulationFindingArtifact> {
  return api.get<SimulationFindingArtifact>(
    `${V1}/${encodeURIComponent(identityId)}/simulations/${encodeURIComponent(simulationId)}/export`,
  );
}

// ── Bulk Simulation ─────────────────────────────────────────────────

export interface BulkSimulationRequest {
  identity_ids: string[];
  simulation_type: SimulationType;
  payload: Record<string, any>;
}

export interface BulkSimulationResult {
  total: number;
  completed: number;
  failed: number;
  aggregate_score_delta: number;
  aggregate_blast_radius_delta: number;
  simulation_ids: string[];
  failures: { identity_id: string; error: string }[];
}

export async function runBulkSimulation(
  request: BulkSimulationRequest,
): Promise<BulkSimulationResult> {
  return api.post<BulkSimulationResult>(`${POSTURE}/simulate/bulk`, request);
}
