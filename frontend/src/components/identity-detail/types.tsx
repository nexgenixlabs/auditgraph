import React from 'react';
import {
  type IdentityCategory, type RiskLevel,
  RISK_BADGE, DATA_EXPLANATIONS, DORMANT_LABELS,
  safeLower, normalizeCategoryFromBackend, getCategoryLabel, getDormantStatus,
  TIME_MS,
} from '../../constants/metrics';

// Re-export metrics imports used by sibling modules
export type { IdentityCategory, RiskLevel };
export { RISK_BADGE, DATA_EXPLANATIONS, DORMANT_LABELS, safeLower, normalizeCategoryFromBackend, getCategoryLabel, getDormantStatus };

// Re-export verdict SSOT — single definition lives in constants/verdicts.ts
export type { LineageVerdict } from '../../constants/verdicts';
export { verdictBadgeClasses, verdictLabel } from '../../constants/verdicts';

// ─── Interfaces ─────────────────────────────────────────────────────

export interface Owner {
  owner_object_id: string;
  owner_display_name?: string;
  owner_upn?: string;
  owner_type?: string;
  is_primary_owner?: boolean;
}

export interface AttackPattern {
  attack_scenario: string;
  real_world_example: string;
  company_affected: string;
  breach_year: number;
  estimated_cost_usd: number;
  source?: string;
}

export interface HipaaViolation {
  hipaa_section: string;
  violation_explanation: string;
  violation_risk: string;
  typical_penalty_min: number;
  typical_penalty_max: number;
}

export interface RoleIntelligence {
  role_name: string;
  attack_patterns: AttackPattern[];
  hipaa_violations: HipaaViolation[];
}

export interface TrendData {
  previous_risk_level?: string | null;
  previous_risk_score?: number | null;
  risk_direction?: 'worsened' | 'improved' | 'unchanged' | 'new';
  is_new?: boolean;
}

export interface EvidenceMetadata {
  run_id?: number;
  collected_at?: string | null;
  sources?: Record<string, string>;
}

export interface IdentityDetailsResponse {
  run_id: number;
  identity: {
    identity_id: string;
    display_name: string;
    identity_type?: string;
    identity_category?: IdentityCategory;
    risk_level?: RiskLevel;
    risk_score?: number;
    risk_reasons?: string[];

    credential_status?: string;
    credential_count?: number;
    credential_expiration?: string | null;

    created_datetime?: string | null;
    activity_status?: string | null;
    last_sign_in?: string | null;
    last_seen_auth?: string | null;

    enabled?: boolean;
    is_microsoft_system?: boolean;
    is_discovery_connector?: boolean;

    // Effective last used (MAX of observed + Azure sign-in)
    effective_last_used?: string | null;
    effective_last_used_source?: 'auditgraph' | 'azure_signin' | 'inferred_federated' | null;

    // Sign-in authentication provenance
    last_signin_at?: string | null;
    last_signin_ip?: string | null;
    auth_source?: 'entra_signin_log' | 'aad_audit' | 'static_analysis_only';

    object_id?: string | null;
    app_id?: string | null;

    tags?: any;

    cloud?: string;
    normalized_identity_type?: string;
    principal_id?: string;
    tenant_or_org_id?: string;
    owner_display_name?: string | null;
    owner_count?: number;
    api_permission_count?: number;
    app_role_count?: number;
    status?: string;
    status_display?: { label: string; badge_class: string };
    deleted_at?: string | null;
    ca_coverage_status?: string | null;
    ca_mfa_enforced?: boolean;
    has_federated_credentials?: boolean;
    removable_role_count?: number;
    group_count?: number;
    privileged_groups?: { group_name: string; group_type: string; inherited_role_count: number; highest_scope: string }[];
    resource_context?: {
      resource_id: string;
      resource_type: string;
      resource_name: string;
      resource_group: string | null;
      subscription_id: string | null;
      state?: string | null;
      jit_enabled?: boolean | null;
      env_secret_count?: number;
    } | null;
    // Feature D (humans variant) — surfaces directory_audit_log IP enrichment
    // even without P2 telemetry. The aggregate arrays are only populated when
    // P2 sign-in telemetry is enabled.
    signin_intelligence?: {
      last_observed_ip?: string | null;
      last_observed_ip_source?: string | null;
      last_observed_ip_date?: string | null;
      last_observed_operation?: string | null;
      ips?: Array<{ ip: string; classification?: string; count?: number }>;
      locations?: Array<{ city?: string; country?: string; count?: number }>;
      resources_accessed?: Array<{ name?: string; count?: number }>;
      client_apps?: Array<{ name?: string; count?: number }>;
      failure_count_30d?: number | null;
      success_count_30d?: number | null;
      total_events_30d?: number | null;
    };
  };
  roles: any[];
  graph_permissions: any[];
  app_roles: any[];
  owners: Owner[];
  role_intelligence: RoleIntelligence[];
  lineage?: LineageData | null;
  trend?: TrendData | null;
  evidence?: EvidenceMetadata;
}

export interface LineageData {
  narrative: string | null;
  workload_origin: string | null;
  workload_origin_source: string | null;
  provisioned_by: string | null;
  creation_method: string | null;
  verdict: string | null;
  confidence: number | null;
  contributing_factors: Array<{ detail: string; source?: string; weight: number }> | null;
  verdict_source: string | null;
}

export type TabId = 'overview' | 'roles' | 'permissions' | 'credentials' | 'ownership' | 'effective_access' | 'access_graph' | 'anomalies' | 'compliance' | 'pim' | 'remediation' | 'lifecycle' | 'simulate' | 'timeline' | 'sensitive_access';

export interface EffectiveAccessEntry {
  role_name: string;
  role_source: 'azure_rbac' | 'entra_directory';
  access_level: 'Admin' | 'Write' | 'Read';
  category: string;
  scope: string;
  scope_display: string;
  scope_type: string;
  resource_type: string | null;
  risk_level: string;
  assigned_on: string | null;
  permissions: string[];
  why_critical: string | null;
}

export interface EffectiveAccessData {
  identity_id: string;
  display_name: string;
  effective_access: EffectiveAccessEntry[];
  summary: {
    admin_scopes: number;
    write_scopes: number;
    read_scopes: number;
    total_roles: number;
    total_permissions: number;
    categories: string[];
  };
}

export interface RemediationItem {
  id: number;
  title: string;
  description: string;
  steps: string[];
  impact: string;
  effort: string;
  priority_score: number;
  compliance_refs: string[];
  category: string;
  matched_reason: string;
}

export interface RemediationData {
  identity_id: string;
  display_name: string;
  risk_level: string;
  remediations: RemediationItem[];
  summary: {
    total: number;
    critical_actions: number;
    quick_wins: number;
  };
}

export type RemediationStatus = 'open' | 'acknowledged' | 'completed' | 'skipped';

export interface RemediationAction {
  status: RemediationStatus;
  notes: string | null;
  updated_at: string | null;
  execution_status?: string | null;
  execution_log?: {
    action_type?: string;
    result?: string;
    detail?: string;
    simulated?: boolean;
  } | null;
  executed_at?: string | null;
}

export type RemediationActionsMap = Record<number, RemediationAction>;

export interface CvssFix {
  fix_type: string;
  verb: string;
  title: string;
  description: string;
  risk_reduction_pct: number;
  risk_reduction_pts: number;
  current_score: number;
  simulated_score: number;
  simulated_band: string;
  effort_minutes: number;
  execution_safety: string;
  safety_color: string;
  safety_reason: string | null;
  framework_badges: string[];
  impacted_paths: number;
  scope: string;
  priority_score: number;
}

export interface CvssFixResponse {
  identity_id: string;
  organization_id: number;
  fixes: CvssFix[];
  fix_count: number;
  projected_impact: {
    after_all_fixes: {
      simulated_score: number;
      simulated_band: string;
      risk_reduction_pct: number;
      posture_score_delta: number;
    };
  } | null;
}

export interface PimEligible {
  role_name: string;
  role_definition_id?: string;
  directory_scope?: string;
  assignment_type?: string;
  start_datetime?: string | null;
  end_datetime?: string | null;
  member_type?: string;
}

export interface PimActivation {
  role_name: string;
  role_definition_id?: string;
  directory_scope?: string;
  status?: string;
  activation_start?: string | null;
  activation_end?: string | null;
  justification?: string | null;
  ticket_number?: string | null;
  ticket_system?: string | null;
  is_approval_required?: boolean;
  created_datetime?: string | null;
}

export interface PimShouldBePimFinding {
  role_name: string;
  scope: string;
  scope_type: string;
  kind: 'entra' | 'azure';
  has_pim_alt: boolean;
  severity: string;
  recommendation: string;
  frameworks?: {
    cis?: string[];
    nist?: string[];
    mitre?: string[];
  };
}

export interface PimData {
  eligible_assignments: PimEligible[];
  activations: PimActivation[];
  overuse_metrics: {
    activation_frequency_30d: number;
    always_active_pattern: boolean;
    total_active_hours_30d: number;
  };
  // Standing privileged assignments that Microsoft best practice says
  // should be PIM-eligible (just-in-time, time-bound). Computed at
  // API time from identity_subscription_access + entra_role_assignments
  // joined against access_paths.pim_eligible.
  should_be_pim?: PimShouldBePimFinding[];
}

// ─── Utility Functions ──────────────────────────────────────────────

export function formatDate(iso?: string | null) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function daysUntil(iso?: string | null): number | null {
  if (!iso) return null;
  try {
    const diff = new Date(iso).getTime() - Date.now();
    return Math.ceil(diff / TIME_MS.DAY);
  } catch { return null; }
}

export function credentialCountdown(iso?: string | null): React.ReactNode {
  const days = daysUntil(iso);
  if (days == null) return null;
  if (days < 0) return <span className="text-xs font-semibold text-red-600">Expired {Math.abs(days)}d ago</span>;
  if (days === 0) return <span className="text-xs font-semibold text-red-600">Expires today</span>;
  if (days <= 7) return <span className="text-xs font-semibold text-red-600">{days}d remaining</span>;
  if (days <= 30) return <span className="text-xs font-semibold text-orange-600">{days}d remaining</span>;
  if (days <= 90) return <span className="text-xs font-semibold text-yellow-600">{days}d remaining</span>;
  return <span className="text-xs text-green-600">{days}d remaining</span>;
}

export function formatUsd(n?: number): string {
  if (n == null || n === 0) return '—';
  if (n >= 1_000_000_000) return `$${(n / 1_000_000_000).toFixed(1)}B`;
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n.toLocaleString()}`;
}

export function violationRiskColor(risk?: string): string {
  return RISK_BADGE[safeLower(risk)] || 'bg-gray-100 text-gray-600';
}

export function riskBadge(level?: string) {
  const v = safeLower(level);
  const base = 'px-2 py-1 rounded-full text-xs font-semibold inline-flex items-center';
  return <span className={`${base} ${RISK_BADGE[v] || 'bg-gray-100 text-gray-700'}`}>{(v || 'unknown').toUpperCase()}</span>;
}

export function categoryLabel(catRaw?: any, typeRaw?: any) {
  const cat = normalizeCategoryFromBackend(catRaw);
  if (cat !== 'unknown') return getCategoryLabel(cat);
  // Fallback to type-based lookup
  return getCategoryLabel(safeLower(typeRaw)) || 'Unknown';
}

// ─── Evidence / Data Source component (Pillar 5) ────────────────────

export function DataSource({ label, apiSource, collectedAt }: { label: string; apiSource?: string; collectedAt?: string | null }) {
  return (
    <div className="flex items-center gap-2 text-[10px] text-gray-400 mt-1">
      <svg className="w-3 h-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
      </svg>
      <span>
        Source: <span className="text-gray-500 font-medium">{label}</span>
        {apiSource && <span className="ml-1 font-mono">{apiSource}</span>}
        {collectedAt && <span className="ml-1">· Collected {new Date(collectedAt).toLocaleDateString()}</span>}
      </span>
    </div>
  );
}

// ─── Privilege tier / Effective access helpers ──────────────────────

export const TIER_CONFIG: Record<number, { label: string; name: string; color: string; borderColor: string; description: string }> = {
  0: { label: 'T0', name: 'Control Plane', color: 'bg-red-100 text-red-800 border-red-300', borderColor: 'border-red-200', description: 'Full tenant control — Global Admin, Privileged Role Admin' },
  1: { label: 'T1', name: 'Management Plane', color: 'bg-orange-100 text-orange-800 border-orange-300', borderColor: 'border-orange-200', description: 'Broad management access — User Admin, Exchange Admin, sub Owner' },
  2: { label: 'T2', name: 'Data / App Plane', color: 'bg-yellow-100 text-yellow-800 border-yellow-300', borderColor: 'border-yellow-200', description: 'Scoped data/app access — Contributor, Key Vault, risky Graph API perms' },
  3: { label: 'T3', name: 'Standard', color: 'bg-gray-100 text-gray-600 border-gray-300', borderColor: 'border-gray-200', description: 'No privileged roles — Reader, limited access' },
};

export function computePrivilegeTier(roles: any[], graphPerms: any[]): { tier: number; reasons: string[] } {
  const reasons: string[] = [];
  let maxTier = 3;

  const t0Roles = ['Global Administrator', 'Privileged Role Administrator', 'Partner Tier2 Support'];
  const t1Roles = ['User Administrator', 'Exchange Administrator', 'Intune Administrator', 'Security Administrator', 'Compliance Administrator'];
  const t0Scopes = ['Owner'];
  const t1Scopes = ['Contributor'];

  for (const r of roles) {
    const name = r.role_name || '';
    const type = safeLower(r.role_type);
    const scope = r.scope || '';

    if (type === 'entra') {
      if (t0Roles.some(t => name.includes(t))) {
        if (maxTier > 0) maxTier = 0;
        reasons.push(`Entra: ${name}`);
      } else if (t1Roles.some(t => name.includes(t))) {
        if (maxTier > 1) maxTier = 1;
        reasons.push(`Entra: ${name}`);
      } else if (maxTier > 2) {
        maxTier = 2;
        reasons.push(`Entra: ${name}`);
      }
    } else {
      // Azure RBAC
      const isSubScope = scope.match(/^\/subscriptions\/[^/]+$/) || scope === '/';
      if (t0Scopes.some(t => name.includes(t)) && isSubScope) {
        if (maxTier > 0) maxTier = 0;
        reasons.push(`RBAC: ${name} at ${scope.substring(0, 60)}`);
      } else if (t1Scopes.some(t => name.includes(t)) && isSubScope) {
        if (maxTier > 1) maxTier = 1;
        reasons.push(`RBAC: ${name} at ${scope.substring(0, 60)}`);
      } else if (safeLower(r.risk_level) === 'critical' || safeLower(r.risk_level) === 'high') {
        if (maxTier > 2) maxTier = 2;
        reasons.push(`RBAC: ${name}`);
      }
    }
  }

  // Check Graph API permissions for T2 elevation
  const riskyPerms = graphPerms.filter(p => safeLower(p.risk_level) === 'critical' || safeLower(p.risk_level) === 'high');
  if (riskyPerms.length > 0 && maxTier > 2) {
    maxTier = 2;
    reasons.push(`${riskyPerms.length} high-risk Graph API permission${riskyPerms.length > 1 ? 's' : ''}`);
  }

  return { tier: maxTier, reasons: reasons.slice(0, 5) };
}

export function parseEffectiveAccessScope(roles: any[]): { subscriptions: string[]; resourceGroups: string[]; tenantWide: boolean; entraScopes: string[] } {
  const subs = new Set<string>();
  const rgs = new Set<string>();
  const entraScopes = new Set<string>();
  let tenantWide = false;

  for (const r of roles) {
    const scope = r.scope || '';
    const type = safeLower(r.role_type);

    if (type === 'entra') {
      entraScopes.add(scope === '/' ? 'Tenant-wide' : scope);
      if (scope === '/') tenantWide = true;
    } else {
      const subMatch = scope.match(/\/subscriptions\/([^/]+)/);
      if (subMatch) subs.add(subMatch[1]);
      const rgMatch = scope.match(/\/resourceGroups\/([^/]+)/);
      if (rgMatch) rgs.add(rgMatch[1]);
      if (scope === '/') tenantWide = true;
    }
  }

  return { subscriptions: Array.from(subs), resourceGroups: Array.from(rgs), tenantWide, entraScopes: Array.from(entraScopes) };
}
