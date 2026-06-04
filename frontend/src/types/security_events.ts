/**
 * AG-177 (Shared Infra): Canonical TypeScript types for security events
 * consumed by AttackPathView, AILifecycleTimeline, AgentActivityTimeline,
 * AgentTrustScoreCard, and Argus.
 *
 * Single source of truth — any component that renders a path node or
 * timeline event must import these types instead of redefining locally.
 */

// ─── MITRE ATT&CK ────────────────────────────────────────────────────────

export interface MitreTechnique {
  id: string;          // e.g. "T1552.001"
  name: string;
  tactic: string;      // e.g. "Credential Access"
  tactic_id?: string;  // e.g. "TA0006"
  description?: string;
  url?: string;        // e.g. https://attack.mitre.org/techniques/T1552/001/
}

// ─── Path nodes (attack chains) ─────────────────────────────────────────

export type PathNodeType =
  | 'ai_agent'
  | 'human_user'
  | 'service_principal'
  | 'managed_identity'
  | 'workload_identity'
  | 'rbac_role'
  | 'entra_role'
  | 'key_vault'
  | 'kv_secret'
  | 'storage_account'
  | 'sql_database'
  | 'cosmos_database'
  | 'data_classification'
  | 'network_egress'
  | 'subscription'
  | 'resource_group'
  | 'resource';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface PathNode {
  node_type: PathNodeType;
  label: string;
  description?: string;
  mitre_techniques?: MitreTechnique[];   // populated by enrich_path_node_with_mitre
  tactic_stage?: string;                  // e.g. "Initial Access", "Credential Access"
  evidence_id?: string;                   // identity_id / resource_id / role_assignment_id
  severity?: Severity;
  risk_contribution?: number;             // points added to total path risk
  classification?: string;                // PHI / PCI / PII / Source / HR / Financial / Confidential
  // Visual hints (optional)
  icon?: string;
  color?: string;
}

export interface AttackPathRow {
  id: number;
  path_type: string;                      // e.g. 'ai_agent_exfiltration'
  source_entity_id: string;
  source_entity_type: string;
  target_resource_id: string;
  target_resource_type: string;
  severity: Severity;
  risk_score: number;
  affected_resource_count: number;
  path_nodes: PathNode[];
  narrative?: string | null;
  organization_id: number;
  discovery_run_id: number;
  created_at: string;
}

// ─── Lifecycle events (J/M/L for AI agents and humans) ──────────────────

export type LifecycleEventType =
  | 'identity_added'
  | 'identity_removed'
  | 'identity_disabled'
  | 'identity_reactivated'
  | 'role_assigned'
  | 'role_removed'
  | 'privilege_escalated'
  | 'privilege_deescalated'
  | 'owner_changed'
  | 'model_changed'                       // AI-specific
  | 'model_version_bumped'
  | 'deployment_added'
  | 'deployment_removed'
  | 'capacity_expanded'
  | 'ai_permissions_escalated'
  | 'ai_owner_changed'
  | 'ai_agent_joiner'
  | 'ai_agent_mover'
  | 'ai_agent_leaver';

export interface LifecycleEvent {
  event_type: LifecycleEventType;
  identity_id: string;
  identity_db_id: number;
  run_id: number;
  occurred_at: string;
  severity: Severity;
  before?: Record<string, unknown> | null;
  after?: Record<string, unknown> | null;
  description: string;
  mitre_techniques?: MitreTechnique[];
}

// ─── Activity timeline events (behavior baseline) ───────────────────────

export type ActivityEventCategory =
  | 'model_call'
  | 'secret_read'
  | 'data_access'
  | 'permission_change'
  | 'auth_event'
  | 'anomaly';

export interface ActivityEvent {
  event_id: string;
  identity_db_id: number;
  category: ActivityEventCategory;
  occurred_at: string;
  source: string;                         // 'azure_monitor' | 'arm_activity_log' | 'graph_audit'
  resource_id?: string;
  resource_type?: string;
  metric_value?: number;                  // e.g. records read, tokens generated
  baseline_value?: number;                // for anomaly detection
  severity?: Severity;
  description: string;
}

// ─── Trust Score (AG-179) ──────────────────────────────────────────────

export type TrustGrade =
  | 'PASS' | 'FAIL'                       // Ownership / Egress / Oversight / Network / Supply Chain
  | 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'   // Secrets / Data Access
  | 'PARTIAL' | 'FULL'                   // Telemetry
  | 'ONE' | 'MULTI';                      // Model Exposure (AG-T1.3)

export interface TrustDimension {
  grade: TrustGrade;
  evidence: string;
  role_name?: string | null;
  scope?: string | null;
  count?: number;                         // Model Exposure carries count
}

export interface AgentTrust {
  identity_id: string;
  identity_db_id: number;
  trust_score: number;                    // 0-100
  ownership: TrustDimension;
  secrets: TrustDimension;
  egress: TrustDimension;
  telemetry: TrustDimension;
  oversight: TrustDimension;
  // AG-T1.3: 4 new dimensions (5 → 9)
  data_access: TrustDimension;
  network: TrustDimension;
  model_exposure: TrustDimension;
  supply_chain: TrustDimension;
  computed_at: string;
}

export interface BoardScorecard {
  organization_id: number;
  snapshot_date: string;
  total_agents: number;
  with_owner_pct: number;
  with_telemetry_pct: number;
  private_network_pct: number;
  least_privilege_pct: number;
  policy_compliant_pct: number;
  distribution: {
    strong: number;
    good: number;
    elevated: number;
    critical: number;
  };
  top_10_worst: Array<{
    identity_id: string;
    display_name: string;
    trust_score: number;
    top_dimension_fail: string;
  }>;
  exceptions_pending: number;
}

// ─── Data Classification ───────────────────────────────────────────────

export const CLASS_COLORS: Record<string, string> = {
  PHI: '#dc2626',
  PCI: '#ea580c',
  PII: '#f59e0b',
  SOURCE: '#2563eb',
  HR: '#7c3aed',
  FINANCIAL: '#0891b2',
  CONFIDENTIAL: '#6b7280',
};

export interface ClassificationResult {
  classification: keyof typeof CLASS_COLORS;
  confidence: 'high' | 'medium' | 'low';
  source: 'tag' | 'name_pattern' | 'override';
}
