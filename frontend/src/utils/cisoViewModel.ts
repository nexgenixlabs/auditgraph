/**
 * CISO View Model — Pure Transformation Layer
 *
 * Converts raw `/api/risk/summary/full` + `/api/overview/attack-surface-score`
 * responses into a CISO-friendly view model.
 *
 * SSOT: total_identities is the single source of truth.
 * Every metric derives from it and is expressed as count + percentage.
 *
 * No side effects, no API calls, no React hooks.
 */

import { formatRelativeTime } from './displayHelpers';

// ── Helpers ──────────────────────────────────────────────────

/** Round to 1 decimal: 4.2, 12.0, 0.3 */
function pct(count: number, total: number): number {
  if (total <= 0) return 0;
  return Math.round((count / total) * 1000) / 10;
}

/** Format percentage for display: "4.2%" or "<0.1%" */
export function fmtPct(value: number): string {
  if (value <= 0) return '0%';
  if (value < 0.1) return '<0.1%';
  return `${value}%`;
}

// ── Posture v3.1 Response Types ──────────────────────────────

export interface PostureV31BlastRadius {
  identity_id: number;
  identity_name: string;
  identity_string_id: string | null;
  risk_score: number;
  role_tier: string;
  scope_string: string;
  exploitation_text: string;
  impact_label?: string;
}

export interface PostureV31AttackPath {
  identity_id?: number;
  identity_string_id?: string | null;
  identity_name: string;
  actor?: string;
  role_tier?: string;
  target?: string;
  risk_score: number;
  // Persisted attack path fields
  id?: number;
  path_type?: string;
  severity?: string;
  description?: string;
  affected_resource_count?: number;
  narrative?: string;
}

export interface PostureV31Coverage {
  active_sources: number;
  total_sources: number;
  sub_count: number;
  cloud_label: string;
  confidence_level: 'high' | 'medium' | 'low';
  coverage_pct: number;
}

export interface PostureV31PriorityAction {
  rank: number;
  action?: string;
  title?: string;
  detail?: string;
  description?: string;
  impact_description?: string;
  impact_level?: string;
  impact_tag?: string;
  affected_count?: number;
  affected_identities?: number;
  total_affected?: number;
  scope_label?: string;
  blast_reduction_pct?: number;
  risk_reduction_pct?: number;
  compliance_tags?: string[];
  framework_badges?: string[];
  is_quick_win?: boolean;
  execution_safety?: string;
  safety_color?: string;
  verb?: string;
  effort_estimate?: string;
  route?: string;
}

export interface PostureV31DriftChange {
  type: string;
  count: number;
}

export interface PostureV31Response {
  posture_score: number;
  posture_status: 'STRONG' | 'MODERATE' | 'WEAK';
  score_delta: number | null;
  narrative_text: string;
  top_risk_narrative: string | null;
  highest_risk_type: string | null;
  identity_risk: {
    dormant: number;
    ghost: number;
    unowned_nhi: number;
    machine_pct: number;
    total: number;
  };
  coverage: PostureV31Coverage;
  blast_radius: PostureV31BlastRadius | null;
  attack_paths: PostureV31AttackPath[];
  attack_path_total?: number;
  attack_path_source_count?: number;
  scan_metadata: {
    last_scan_at: string | null;
    scan_duration_seconds: number | null;
    scan_count: number;
    tenant_domain: string | null;
  };
  // Full fields (only present with ?include=full)
  immediate_risks?: Array<{
    type: string;
    count: number;
    severity: string;
    label: string;
  }>;
  if_unaddressed_count?: number;
  has_overlapping_identities?: boolean;
  priority_actions?: PostureV31PriorityAction[];
  anomalies?: Array<{
    id: number;
    type: string;
    severity: string;
    identity_name: string;
    identity_id: number | string | null;
    created_at: string | null;
  }>;
  business_impact?: {
    inactive_admin_count: number;
    disabled_live_rbac_count: number;
  };
  drift?: {
    has_drift: boolean;
    total_changes: number;
    changes: PostureV31DriftChange[];
    detected_at: string | null;
  } | null;
  projected?: {
    score: number;
    status: string;
    at_risk_count: number;
    score_improvement: number;
    actions_applied: number;
    risk_reduction_pct: number;
  };
}

// ── Extended VM Sub-Types ─────────────────────────────────────

export interface TrendHistory {
  available: boolean;
  runs: string[];            // ISO timestamps
  posture_scores: number[];  // AGIRS scores per run
  direction: 'improving' | 'declining' | 'stable' | null;
  delta_narrative: string;
}

export interface AnomalySummary {
  available: boolean;
  unresolved: number;
  by_severity: Record<string, number>;
  top_anomalies: Array<{ type: string; severity: string; identity_name: string; created_at: string }>;
  narrative: string;
}

export interface RemediationProgress {
  available: boolean;
  open: number;
  completed: number;
  total: number;
  completion_pct: number;
  narrative: string;
}

export interface DriftSummary {
  available: boolean;
  has_drift: boolean;
  total_changes: number;
  permission_changes: number;
  role_changes: number;
  credential_changes: number;
  narrative: string;
}

export interface SPNExposure {
  available: boolean;
  total_custom: number;
  critical: number;
  expired_creds: number;
  orphaned_privileged: number;
  narrative: string;
}

// ── Output: What the CISO dashboard renders ──────────────────

export interface CISOViewModel {
  status: 'low' | 'moderate' | 'high' | 'critical' | 'no_data';
  status_label: string;
  status_reason: string;
  trend: 'improving' | 'declining' | 'stable' | null;

  /** SSOT base metric — all percentages derive from this */
  total_identities: number;

  monitored: {
    identities: number;
    subscriptions: number | null;
    active_subscriptions: number;
  };

  /** (critical + high) / total — headline risk metric */
  risk_exposure: {
    count: number;
    pct: number;
    level: 'low' | 'moderate' | 'high' | 'critical';
    nav: string;
  };

  top_risk_drivers: Array<{
    title: string;
    count: number;
    pct: number;                // count / total_identities
    severity: 'critical' | 'high' | 'medium';
    narrative: string;          // includes count + pct
    nav: string;
  }>;

  blast_radius: {
    level: 'low' | 'medium' | 'high' | 'critical';
    identity_name: string | null;
    identity_id: number | null;
    identity_string_id: string | null;
    summary: string;
    consequences: string[];
  };

  immediate_actions: Array<{
    action: string;
    detail: string;
    nav: string;
  }>;

  business_impact: Array<{
    text: string;
    level: 'red' | 'orange' | 'yellow' | 'green';
  }>;

  system_assessment: string;

  snapshot: {
    risk_distribution: Array<{ level: string; count: number; pct: number; nav: string }>;
    identity_types: Array<{ type: string; count: number; pct: number }>;
  };

  last_updated: string;
  data_confidence: 'high' | 'medium' | 'low';
  coverage_pct: number;
  confidence_reason: string;
  data_origin: 'tenant_scan' | 'no_data' | 'unknown';

  /** AGIRS composite score for badge display */
  agirs_display: {
    score: number | null;
    tier: string | null;
    nav: string;
    identities_at_risk: number;
  };

  /** Navigation URL for total identities count */
  total_identities_nav: string;

  /** Per-category identity breakdown for metric cards */
  identity_categories: Array<{
    label: string;
    count: number;
    pct: number;
    issues: string[];
    tag: { text: string; variant: string };
    accent: string;
    chart_color: string;
    nav: string;
  }>;

  /** Top dangerous identities for findings table */
  findings: Array<{
    name: string;
    sub: string;
    verdict: string;
    verdict_variant: string;
    blast_pct: number;
    blast_color: string;
    blast_label: string;
    action_label: string;
    nav: string;
    /** Pre-populated metadata for drawer (avoids blank name on load). */
    prefill: { display_name?: string; identity_category?: string; risk_level?: string; risk_score?: number };
  }>;

  // ── Extended data (from additional API endpoints) ──
  trend_history: TrendHistory;
  anomaly_summary: AnomalySummary;
  remediation_progress: RemediationProgress;
  drift_summary: DriftSummary;
  spn_exposure: SPNExposure;
  composition_insights: string[];
}

// ── Risk Driver Definitions ──────────────────────────────────

interface RiskDriverDef {
  title: string;
  severity: 'critical' | 'high' | 'medium';
  narrative: (n: number, p: number) => string;     // count, pct
  action: (n: number, p: number) => string;
  action_detail: string;
  nav: string;
}

const RISK_DRIVER_MAP: Record<string, RiskDriverDef> = {
  dormant_privileged: {
    title: 'Dormant Privileged Accounts',
    severity: 'critical',
    narrative: (n, p) => `${n} account${n !== 1 ? 's' : ''} (${fmtPct(p)} of all identities) with admin access ${n !== 1 ? 'have' : 'has'} been inactive for 90+ days — silent attack vectors with standing admin control.`,
    action: (n, p) => `Revoke admin roles from ${n} dormant account${n !== 1 ? 's' : ''} (${fmtPct(p)})`,
    action_detail: 'Eliminate standing privilege on inactive accounts immediately',
    nav: '/identities?metric=dormant&pillar=effective-privilege',
  },
  ghost_accounts: {
    title: 'Ghost Identities',
    severity: 'critical',
    narrative: (n, p) => `${n} disabled or deleted identit${n !== 1 ? 'ies' : 'y'} (${fmtPct(p)}) still hold${n === 1 ? 's' : ''} active RBAC roles — invisible backdoors into your environment.`,
    action: (n, p) => `Remove all RBAC from ${n} ghost identit${n !== 1 ? 'ies' : 'y'} (${fmtPct(p)})`,
    action_detail: 'Strip role assignments from disabled/deleted identities',
    nav: '/identities?metric=ghost',
  },
  orphaned_spns: {
    title: 'Unowned Service Principals',
    severity: 'high',
    narrative: (n, p) => `${n} service principal${n !== 1 ? 's' : ''} (${fmtPct(p)}) operate${n === 1 ? 's' : ''} without an owner — unaccountable access with no human oversight.`,
    action: (n, p) => `Assign owners to ${n} orphaned service principal${n !== 1 ? 's' : ''} (${fmtPct(p)})`,
    action_detail: 'Enforce ownership policy before next compliance review',
    nav: '/identities?metric=unowned_nhi',
  },
  over_privileged: {
    title: 'Excess Privilege',
    severity: 'high',
    narrative: (n, p) => `${n} identit${n !== 1 ? 'ies' : 'y'} (${fmtPct(p)}) hold${n === 1 ? 's' : ''} Owner or Contributor roles not exercised in 90+ days — unnecessary blast radius.`,
    action: (n, p) => `Revoke unused roles from ${n} over-privileged identit${n !== 1 ? 'ies' : 'y'} (${fmtPct(p)})`,
    action_detail: 'Enforce least-privilege — strip roles with no recent activity',
    nav: '/identities?pillar=effective-privilege',
  },
  external_exposure: {
    title: 'External Guest Privilege',
    severity: 'high',
    narrative: (n, p) => `${n} guest${n !== 1 ? 's' : ''} (${fmtPct(p)}) from external organizations hold${n === 1 ? 's' : ''} privileged roles — supply-chain attack surface.`,
    action: (n, p) => `Restrict ${n} external guest account${n !== 1 ? 's' : ''} (${fmtPct(p)}) to time-bound access`,
    action_detail: 'Convert standing roles to PIM-eligible or revoke entirely',
    nav: '/identities?identity_category=guest&hasRoles=true',
  },
};

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2 };

const STATUS_LABELS: Record<string, string> = {
  low: 'LOW RISK',
  moderate: 'MODERATE RISK',
  high: 'HIGH RISK',
  critical: 'CRITICAL RISK',
  no_data: 'NO DATA',
};

// ── Empty View Model ─────────────────────────────────────────

export function buildEmptyCISOViewModel(): CISOViewModel {
  return {
    status: 'no_data',
    status_label: 'NO DATA',
    status_reason: 'No identity data available. Connect your Azure tenant and run discovery.',
    trend: null,
    total_identities: 0,
    monitored: { identities: 0, subscriptions: null, active_subscriptions: 0 },
    risk_exposure: { count: 0, pct: 0, level: 'low', nav: '/identities' },
    top_risk_drivers: [],
    blast_radius: {
      level: 'low',
      identity_name: null,
      identity_id: null,
      identity_string_id: null,
      summary: 'No blast radius data available.',
      consequences: [],
    },
    immediate_actions: [],
    business_impact: [],
    system_assessment: '',
    snapshot: { risk_distribution: [], identity_types: [] },
    last_updated: 'Never',
    data_confidence: 'low',
    coverage_pct: 0,
    confidence_reason: '',
    data_origin: 'no_data',
    agirs_display: { score: null, tier: null, nav: '/identities', identities_at_risk: 0 },
    total_identities_nav: '/identities',
    identity_categories: [],
    findings: [],
    trend_history: { available: false, runs: [], posture_scores: [], direction: null, delta_narrative: '' },
    anomaly_summary: { available: false, unresolved: 0, by_severity: {}, top_anomalies: [], narrative: '' },
    remediation_progress: { available: false, open: 0, completed: 0, total: 0, completion_pct: 0, narrative: '' },
    drift_summary: { available: false, has_drift: false, total_changes: 0, permission_changes: 0, role_changes: 0, credential_changes: 0, narrative: '' },
    spn_exposure: { available: false, total_custom: 0, critical: 0, expired_creds: 0, orphaned_privileged: 0, narrative: '' },
    composition_insights: [],
  };
}

// ── Finding Helpers ──────────────────────────────────────────

function inferVerdict(identity: Record<string, any>): { verdict: string; variant: string; action: string } {
  const factors = (identity.key_risk_factors || []).join(' ').toLowerCase();
  const cat = identity.identity_category || '';

  if (factors.includes('orphan') || factors.includes('no owner') || factors.includes('unowned'))
    return { verdict: 'ORPHANED', variant: 'red', action: 'REVOKE' };
  if (factors.includes('ghost') || factors.includes('disabled'))
    return cat.includes('managed_identity')
      ? { verdict: 'GHOST_MSI', variant: 'purple', action: 'REVIEW' }
      : { verdict: 'GHOST', variant: 'red', action: 'REVOKE' };
  if (factors.includes('dormant') || factors.includes('stale') || factors.includes('inactive'))
    return { verdict: 'STALE', variant: 'amber', action: 'DISABLE' };
  if (factors.includes('over') || factors.includes('excessive'))
    return { verdict: 'AT_RISK', variant: 'orange', action: 'SCOPE' };
  if (factors.includes('federated') || factors.includes('credential'))
    return { verdict: 'CRED_RISK', variant: 'orange', action: 'FIX' };
  if (cat === 'guest')
    return { verdict: 'NEEDS_REVIEW', variant: 'teal', action: 'REVIEW' };
  return { verdict: 'AT_RISK', variant: 'orange', action: 'REVIEW' };
}

function buildFindingSub(identity: Record<string, any>): string {
  const catMap: Record<string, string> = {
    service_principal: 'Service Account', managed_identity_system: 'System MSI',
    managed_identity_user: 'User MSI', human_user: 'Human',
    guest: 'Guest', microsoft_internal: 'Microsoft',
  };
  const cat = catMap[identity.identity_category] || identity.identity_category || 'Unknown';
  const factors = identity.key_risk_factors || [];
  const parts = [cat];
  if (factors.length > 0) parts.push(factors[0]);
  const subs = identity.subscription_count || 0;
  if (subs > 1) parts.push(`${subs} subs`);
  return parts.join(' · ');
}

function inferBlastLabel(identity: Record<string, any>): { label: string; color: string } {
  const subs = identity.subscription_count || 0;
  const rgs = identity.resource_group_count || 0;
  const score = identity.blast_radius_score || 0;
  const color = score >= 70 ? '#e8465a' : score >= 40 ? '#FF7216' : '#f59e0b';
  if (subs > 1) return { label: `Blast: ${subs} subs`, color };
  if (subs === 1) return { label: 'Blast: Sub-wide', color };
  if (rgs > 1) return { label: `Blast: ${rgs} RGs`, color };
  if (rgs === 1) return { label: 'Blast: RG scope', color };
  return { label: 'Blast: Limited', color };
}

function buildIdentityCategories(
  ic: Record<string, any>,
  rc: Record<string, any>,
  total: number,
): CISOViewModel['identity_categories'] {
  const cats: CISOViewModel['identity_categories'] = [];

  const spnCount = ic.service_principal || 0;
  const sysMsi = ic.managed_identity_system || 0;
  const userMsi = ic.managed_identity_user || 0;
  const guestCount = ic.guest || 0;
  // Human = Member users only (exclude guests to prevent double-counting)
  const rawHuman = ic.human || ic.human_user || 0;
  const humanCount = Math.max(0, rawHuman - guestCount);
  // Fallback: if no detailed NHI breakdown, estimate SPNs from nhi total
  const nhiTotal = ic.nhi || 0;
  const spnFinal = spnCount || Math.max(0, nhiTotal - sysMsi - userMsi);

  // Sanity check: segments must be mutually exclusive and sum to total
  const nhiSegment = spnFinal + sysMsi + userMsi;
  const segmentSum = humanCount + nhiSegment + guestCount;
  if (total > 0 && segmentSum !== total) {
    console.warn(
      `[AuditGraph] Donut segments (${segmentSum}) do not equal total (${total}). ` +
      `Check for overlapping identity type filters.`,
      { humanCount, rawHuman, guestCount, spnFinal, sysMsi, userMsi, nhiSegment, total },
    );
  }

  if (humanCount > 0) {
    const issues: string[] = [];
    if (rc.dormant_privileged) issues.push(`${rc.dormant_privileged} dormant privileged`);
    if (rc.ghost_accounts) issues.push(`${rc.ghost_accounts} ghost identit${rc.ghost_accounts !== 1 ? 'ies' : 'y'}`);
    if (issues.length === 0) issues.push('No critical issues');
    const crit = (rc.dormant_privileged || 0) + (rc.ghost_accounts || 0);
    cats.push({
      label: 'Human Identities', count: humanCount, pct: pct(humanCount, total), issues,
      tag: crit > 0 ? { text: `${crit} critical`, variant: 'red' } : { text: 'Healthy', variant: 'green' },
      accent: '#e8465a', chart_color: '#4f9de8', nav: '/identities?identity_category=human_user',
    });
  }

  if (spnFinal > 0) {
    const issues: string[] = [];
    if (rc.orphaned_spns) issues.push(`${rc.orphaned_spns} orphaned`);
    if (rc.expired_credentials) issues.push(`${rc.expired_credentials} stale secret${rc.expired_credentials !== 1 ? 's' : ''}`);
    if (issues.length === 0) issues.push('No ownership issues');
    cats.push({
      label: 'Non-Human / SPNs', count: spnFinal, pct: pct(spnFinal, total), issues,
      tag: (rc.orphaned_spns || 0) > 0 ? { text: `${rc.orphaned_spns} at-risk`, variant: 'orange' } : { text: 'Healthy', variant: 'green' },
      accent: '#FF7216', chart_color: '#24A2A1', nav: '/workload-identities?type=spn',
    });
  }

  if (sysMsi > 0) {
    cats.push({
      label: 'System MSIs', count: sysMsi, pct: pct(sysMsi, total),
      issues: ['System-assigned identities', `${sysMsi} tracked`],
      tag: { text: `${sysMsi} tracked`, variant: 'teal' },
      accent: '#f59e0b', chart_color: '#FF7216', nav: '/workload-identities?type=managed_identity',
    });
  }

  if (userMsi > 0) {
    cats.push({
      label: 'User-Assigned MSIs', count: userMsi, pct: pct(userMsi, total),
      issues: ['User-assigned identities', `${userMsi} tracked`],
      tag: { text: 'Tracked', variant: 'green' },
      accent: '#22c55e', chart_color: '#f59e0b', nav: '/workload-identities?type=managed_identity',
    });
  }

  if (guestCount > 0) {
    const issues: string[] = [];
    if (rc.external_exposure) issues.push(`${rc.external_exposure} privileged guest${rc.external_exposure !== 1 ? 's' : ''}`);
    if (issues.length === 0) issues.push('No access issues');
    cats.push({
      label: 'Guest Users', count: guestCount, pct: pct(guestCount, total), issues,
      tag: (rc.external_exposure || 0) > 0 ? { text: `${rc.external_exposure} review needed`, variant: 'orange' } : { text: 'Healthy', variant: 'green' },
      accent: '#24A2A1', chart_color: '#a78bfa', nav: '/identities?identity_category=guest',
    });
  }

  return cats;
}

// ── Core Transformation ──────────────────────────────────────

export function buildCISOViewModel(
  riskData: Record<string, any> | null,
  attackData: Record<string, any> | null,
): CISOViewModel {
  if (!riskData && !attackData) return buildEmptyCISOViewModel();

  const vm = buildEmptyCISOViewModel();

  // ── Data origin ──
  const origin = riskData?.data_origin || 'unknown';
  vm.data_origin = origin === 'tenant_scan' ? 'tenant_scan' : origin === 'no_data' ? 'no_data' : 'unknown';

  // ── Last updated ──
  vm.last_updated = formatRelativeTime(attackData?.data_integrity?.last_scan);

  // ── SSOT: total_identities (customer only — excludes microsoft_internal) ──
  const rawIc = riskData?.identity_counts || {};
  // Merge guest count from attack_surface if identity_counts has none (avoids mutating API response)
  const ic: Record<string, any> = {
    ...rawIc,
    guest: rawIc.guest || riskData?.attack_surface?.external || 0,
  };
  const exp = riskData?.exposure || {};
  const total = ic.customer || ic.total || attackData?.total_identities || 0;
  vm.total_identities = total;
  vm.total_identities_nav = '/identities';
  vm.monitored.identities = total;
  vm.monitored.subscriptions = exp.subscriptions ?? null;
  vm.monitored.active_subscriptions = exp.active_subscriptions ?? 0;

  // ── Confidence + reasoning ──
  const confidence = attackData?.data_integrity?.confidence;
  vm.data_confidence = confidence === 'High' ? 'high' : confidence === 'Medium' ? 'medium' : 'low';
  vm.confidence_reason = buildConfidenceReason(vm);

  // ── Status (from AGIRS score — score itself is never exposed) ──
  const agirs = riskData?.agirs;
  if (agirs && agirs.score != null) {
    const s = agirs.score;
    if (s >= 80) vm.status = 'low';
    else if (s >= 60) vm.status = 'moderate';
    else if (s >= 40) vm.status = 'high';
    else vm.status = 'critical';
  } else {
    vm.status = total > 0 ? 'moderate' : 'no_data';
  }
  vm.status_label = STATUS_LABELS[vm.status];

  // ── Trend (from AGIRS delta — numeric delta never exposed) ──
  const delta = agirs?.delta;
  if (delta != null && delta !== 0) {
    vm.trend = delta > 0 ? 'improving' : 'declining';
  } else if (delta === 0) {
    vm.trend = 'stable';
  } else {
    vm.trend = null;
  }

  // ── Risk counts → drivers (with SSOT percentages) ──
  const rc = riskData?.risk_counts || {};
  const driverCounts: Record<string, number> = {
    dormant_privileged: rc.dormant_privileged || 0,
    ghost_accounts: rc.ghost_accounts || 0,
    orphaned_spns: rc.orphaned_spns || 0,
    over_privileged: rc.over_privileged || 0,
    external_exposure: rc.external_exposure || 0,
  };

  // Build status_reason from counts — now with percentages
  const criticalSum = (driverCounts.ghost_accounts) + (driverCounts.dormant_privileged);
  const highSum = (driverCounts.orphaned_spns) + (driverCounts.over_privileged) + (driverCounts.external_exposure);
  const criticalCategories = (driverCounts.ghost_accounts > 0 ? 1 : 0) + (driverCounts.dormant_privileged > 0 ? 1 : 0);
  const highCategories = (driverCounts.orphaned_spns > 0 ? 1 : 0) + (driverCounts.over_privileged > 0 ? 1 : 0) + (driverCounts.external_exposure > 0 ? 1 : 0);

  if (criticalCategories > 0 || highCategories > 0) {
    const totalExposed = criticalSum + highSum;
    const exposurePct = pct(totalExposed, total);
    const parts: string[] = [];
    if (criticalCategories > 0) parts.push(`${criticalCategories} critical`);
    if (highCategories > 0) parts.push(`${highCategories} high-risk`);
    vm.status_reason = `${parts.join(' and ')} identity exposure${criticalCategories + highCategories > 1 ? 's' : ''} detected — ${totalExposed} identities (${fmtPct(exposurePct)}) at risk`;
  } else if (total > 0) {
    vm.status_reason = `No significant identity exposures detected across ${total.toLocaleString()} monitored identities`;
  }

  // ── Risk exposure metric: (critical + high) / total ──
  const exposureCount = criticalSum + highSum;
  const exposurePctVal = pct(exposureCount, total);
  vm.risk_exposure = {
    count: exposureCount,
    pct: exposurePctVal,
    level: exposurePctVal >= 20 ? 'critical' : exposurePctVal >= 10 ? 'high' : exposurePctVal >= 5 ? 'moderate' : 'low',
    nav: '/identities?risk=critical,high',
  };

  // ── Top risk drivers (max 5, sorted by severity, with pct) ──
  const drivers: CISOViewModel['top_risk_drivers'] = [];
  for (const [key, count] of Object.entries(driverCounts)) {
    if (count <= 0) continue;
    const def = RISK_DRIVER_MAP[key];
    if (!def) continue;
    const p = pct(count, total);
    drivers.push({
      title: def.title,
      count,
      pct: p,
      severity: def.severity,
      narrative: def.narrative(count, p),
      nav: def.nav,
    });
  }
  drivers.sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
  vm.top_risk_drivers = drivers.slice(0, 5);

  // ── Immediate actions (max 4, derived 1:1 from drivers, with pct) ──
  vm.immediate_actions = vm.top_risk_drivers.slice(0, 4).map(driver => {
    const key = Object.keys(driverCounts).find(k => RISK_DRIVER_MAP[k]?.title === driver.title);
    const def = key ? RISK_DRIVER_MAP[key] : null;
    return {
      action: def ? def.action(driver.count, driver.pct) : `Address ${driver.count} (${fmtPct(driver.pct)}) ${driver.title.toLowerCase()}`,
      detail: def?.action_detail || '',
      nav: driver.nav,
    };
  });

  // ── Blast radius ──
  const dangerousIdentities = riskData?.dangerous_identities || [];
  const topIdentity = dangerousIdentities[0];

  if (topIdentity) {
    const subs = topIdentity.subscription_count ?? 0;
    const roles = topIdentity.total_role_count ?? 0;

    vm.blast_radius.level = (subs >= 5 || roles >= 20) ? 'critical'
      : (subs >= 2 || roles >= 10) ? 'high'
      : (subs >= 1 || roles >= 5) ? 'medium' : 'low';

    vm.blast_radius.identity_name = topIdentity.display_name || null;
    vm.blast_radius.identity_id = topIdentity.id || null;
    vm.blast_radius.identity_string_id = topIdentity.identity_id || null;

    vm.blast_radius.summary = topIdentity.display_name
      ? `If ${topIdentity.display_name} is compromised, an attacker could:`
      : 'If this identity is compromised, an attacker could:';

    vm.blast_radius.consequences = buildConsequences(topIdentity, exp);
  } else {
    vm.blast_radius.summary = 'No high-risk identities identified.';
  }

  // ── Business impact ──
  vm.business_impact = buildBusinessImpact(vm, exp);
  vm.system_assessment = buildSystemAssessment(vm);

  // ── Snapshot: risk distribution + identity types (with pct) ──
  // POSTURE CONTRACT: Use backend's actual risk_level counts so drawer
  // drill-down (?risk_level=X) returns exactly the displayed count.
  const rld = riskData?.risk_level_distribution || {};
  const snapCritical = rld.critical || 0;
  const snapHigh = rld.high || 0;
  const snapMedium = rld.medium || 0;
  const snapLow = rld.low || 0;

  const dist: CISOViewModel['snapshot']['risk_distribution'] = [];
  if (snapCritical > 0) dist.push({ level: 'critical', count: snapCritical, pct: pct(snapCritical, total), nav: '/identities?risk_level=critical' });
  if (snapHigh > 0) dist.push({ level: 'high', count: snapHigh, pct: pct(snapHigh, total), nav: '/identities?risk_level=high' });
  if (snapMedium > 0) dist.push({ level: 'medium', count: snapMedium, pct: pct(snapMedium, total), nav: '/identities?risk_level=medium' });
  if (snapLow > 0) dist.push({ level: 'low', count: snapLow, pct: pct(snapLow, total), nav: '/identities?risk_level=low' });
  vm.snapshot.risk_distribution = dist;

  const snapGuestCount = ic.guest || 0;
  const snapHumanCount = Math.max(0, (ic.human || 0) - snapGuestCount);
  const snapNhiCount = ic.nhi || 0;

  const types: CISOViewModel['snapshot']['identity_types'] = [];
  if (snapHumanCount > 0) types.push({ type: 'Human', count: snapHumanCount, pct: pct(snapHumanCount, total) });
  if (snapNhiCount > 0) types.push({ type: 'Non-Human', count: snapNhiCount, pct: pct(snapNhiCount, total) });
  if (snapGuestCount > 0) types.push({ type: 'Guest', count: snapGuestCount, pct: pct(snapGuestCount, total) });
  vm.snapshot.identity_types = types;

  // ── AGIRS badge display ──
  vm.agirs_display = {
    score: riskData?.agirs?.score ?? null,
    tier: riskData?.agirs?.tier ?? null,
    nav: vm.risk_exposure.nav,
    identities_at_risk: vm.risk_exposure.count,
  };

  // ── Identity categories (5 metric cards) ──
  vm.identity_categories = buildIdentityCategories(ic, rc, total);

  // ── Findings from dangerous identities ──
  const dangIdents = riskData?.dangerous_identities || [];
  vm.findings = dangIdents.slice(0, 6).map((di: Record<string, any>) => {
    const v = inferVerdict(di);
    const blast = inferBlastLabel(di);
    return {
      name: di.display_name || 'Unknown',
      sub: buildFindingSub(di),
      verdict: v.verdict,
      verdict_variant: v.variant,
      blast_pct: di.blast_radius_score || 0,
      blast_color: blast.color,
      blast_label: blast.label,
      action_label: v.action,
      nav: di.identity_id || di.id ? `/identities/${di.identity_id || di.id}` : '',
      prefill: {
        display_name: di.display_name || undefined,
        identity_category: di.identity_category || undefined,
        risk_level: di.risk_level || undefined,
        risk_score: di.risk_score ?? undefined,
      },
    };
  });

  return vm;
}

// ── Confidence Reason Builder ────────────────────────────────

function buildConfidenceReason(vm: CISOViewModel): string {
  const total = vm.total_identities;
  const subs = vm.monitored.subscriptions;
  if (total === 0) return 'No identity data ingested — connect a cloud tenant to begin assessment.';

  const subsLabel = subs != null ? `${subs} subscription${subs !== 1 ? 's' : ''}` : null;

  if (vm.data_confidence === 'high') {
    return subsLabel
      ? `Full scan completed across ${total.toLocaleString()} identities and ${subsLabel} — all data sources responded.`
      : `Full scan completed across ${total.toLocaleString()} identities — all data sources responded.`;
  }
  if (vm.data_confidence === 'medium') {
    return `Partial scan coverage — some data sources may not have responded. ${total.toLocaleString()} identities assessed.`;
  }
  return subsLabel
    ? `Limited scan data available — results may be incomplete. ${total.toLocaleString()} identities assessed from ${subsLabel}.`
    : `Limited scan data available — results may be incomplete. ${total.toLocaleString()} identities assessed.`;
}

// ── Finding → Risk Driver Grouping ──────────────────────────

export interface Finding {
  severity: string;
  rule_type: string;
  [key: string]: unknown;
}

export interface RiskDriverGroup {
  title: string;
  count: number;
  severity: string;
}

const FINDING_SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
};

const CATEGORY_TITLES: Record<string, string> = {
  high_privilege_identity: 'High Privilege Identity',
  disabled_account_active_role: 'Ghost Identity with Active Roles',
  orphaned_spn: 'Orphaned Service Principal',
  dormant_privileged: 'Dormant Privileged Account',
  over_privileged: 'Over-Privileged Identities',
  expired_credential: 'Expired Credential',
  zombie_identity: 'Zombie Persona',
  privilege_escalation: 'Privilege Escalation Risk',
  nhi_security: 'Non-Human Identity Risk',
  dormant_identity: 'Dormant Identity',
  excessive_permissions: 'Excessive Permissions',
  credential_risk: 'Credential Risk',
};

export function groupFindingsIntoDrivers(findings: Finding[]): RiskDriverGroup[] {
  const groups = new Map<string, { count: number; severity: string }>();

  for (const f of findings) {
    const cat = f.rule_type || 'unknown';
    const existing = groups.get(cat);
    if (!existing) {
      groups.set(cat, { count: 1, severity: f.severity || 'low' });
    } else {
      existing.count++;
      const cur = FINDING_SEVERITY_ORDER[existing.severity] ?? 9;
      const next = FINDING_SEVERITY_ORDER[f.severity] ?? 9;
      if (next < cur) existing.severity = f.severity;
    }
  }

  const result: RiskDriverGroup[] = [];
  groups.forEach(({ count, severity }, cat) => {
    result.push({
      title: CATEGORY_TITLES[cat] || cat.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase()),
      count,
      severity,
    });
  });

  result.sort((a, b) => {
    const sevDiff = (FINDING_SEVERITY_ORDER[a.severity] ?? 9) - (FINDING_SEVERITY_ORDER[b.severity] ?? 9);
    return sevDiff !== 0 ? sevDiff : b.count - a.count;
  });

  return result.slice(0, 5);
}

// ── Finding → Action Statements ──────────────────────────────

const ACTION_TEMPLATES: Record<string, (n: number) => string> = {
  dormant_privileged:          (n) => `Review ${n} dormant privileged account${n !== 1 ? 's' : ''}`,
  ghost_accounts:              (n) => `Remove roles from ${n} ghost identit${n !== 1 ? 'ies' : 'y'}`,
  disabled_account_active_role:(n) => `Remove roles from ${n} disabled account${n !== 1 ? 's' : ''}`,
  orphaned_spn:                (n) => `Assign owners to ${n} orphaned service principal${n !== 1 ? 's' : ''}`,
  over_privileged:             (n) => `Remove unused roles from ${n} identit${n !== 1 ? 'ies' : 'y'}`,
  external_exposure:           (n) => `Review ${n} external guest account${n !== 1 ? 's' : ''}`,
  expired_credential:          (n) => `Rotate ${n} expired credential${n !== 1 ? 's' : ''}`,
  zombie_identity:             (n) => `Investigate ${n} zombie identit${n !== 1 ? 'ies' : 'y'}`,
  privilege_escalation:        (n) => `Mitigate ${n} privilege escalation risk${n !== 1 ? 's' : ''}`,
  nhi_security:                (n) => `Remediate ${n} non-human identity risk${n !== 1 ? 's' : ''}`,
  dormant_identity:            (n) => `Review ${n} dormant identit${n !== 1 ? 'ies' : 'y'}`,
  excessive_permissions:       (n) => `Reduce permissions on ${n} identit${n !== 1 ? 'ies' : 'y'}`,
  credential_risk:             (n) => `Address ${n} credential risk${n !== 1 ? 's' : ''}`,
  high_privilege_identity:     (n) => `Review ${n} high-privilege identit${n !== 1 ? 'ies' : 'y'}`,
};

export function buildActionStatements(findings: Finding[]): string[] {
  const groups = new Map<string, { count: number; severity: string }>();

  for (const f of findings) {
    const cat = f.rule_type || 'unknown';
    const existing = groups.get(cat);
    if (!existing) {
      groups.set(cat, { count: 1, severity: f.severity || 'low' });
    } else {
      existing.count++;
      const cur = FINDING_SEVERITY_ORDER[existing.severity] ?? 9;
      const next = FINDING_SEVERITY_ORDER[f.severity] ?? 9;
      if (next < cur) existing.severity = f.severity;
    }
  }

  const entries: Array<[string, { count: number; severity: string }]> = [];
  groups.forEach((val, key) => entries.push([key, val]));

  entries.sort((a, b) => {
    const sevDiff = (FINDING_SEVERITY_ORDER[a[1].severity] ?? 9) - (FINDING_SEVERITY_ORDER[b[1].severity] ?? 9);
    return sevDiff !== 0 ? sevDiff : b[1].count - a[1].count;
  });

  return entries.slice(0, 5).map(([cat, { count }]) => {
    const template = ACTION_TEMPLATES[cat];
    if (template) return template(count);
    const label = CATEGORY_TITLES[cat] || cat.replace(/_/g, ' ');
    return `Address ${count} ${label.toLowerCase()} finding${count !== 1 ? 's' : ''}`;
  });
}

// ── Blast Radius Summary ─────────────────────────────────────

export interface BlastRadiusInput {
  role_count: number;
  subscription_count: number;
  scope_summary: string[];
}

const HIGH_PRIVILEGE_ROLES = /^(owner|contributor|user access administrator|global administrator|privileged role administrator)$/i;

export function summarizeBlastRadius(input: BlastRadiusInput): string {
  const { role_count, subscription_count, scope_summary } = input;

  if (role_count === 0 && subscription_count === 0) {
    return 'This identity has no significant blast radius.';
  }

  const privileged = (scope_summary || []).filter(r => HIGH_PRIVILEGE_ROLES.test(r));

  const parts: string[] = [];

  if (subscription_count > 0) {
    parts.push(`access ${subscription_count} subscription${subscription_count !== 1 ? 's' : ''}`);
  }

  if (role_count > 0) {
    let rolePart = `${role_count} role${role_count !== 1 ? 's' : ''}`;
    if (privileged.length > 0) {
      rolePart += ` including ${privileged.join(', ')}`;
    }
    parts.push(rolePart);
  }

  return `If compromised, this identity can ${parts.join(' and ')}.`;
}

// ── Consequence Builder ──────────────────────────────────────

function buildConsequences(
  top: Record<string, any>,
  exposure: Record<string, any>,
): string[] {
  const lines: string[] = [];

  const subs = top.subscription_count ?? 0;
  const totalSubs = exposure.subscriptions ?? 0;
  if (subs > 0 && totalSubs > 0) {
    lines.push(`Control ${subs} of ${totalSubs} Azure subscription${totalSubs !== 1 ? 's' : ''}`);
  }

  const kvs = exposure.key_vaults || 0;
  if (kvs > 0) {
    lines.push(`Access ${kvs} Key Vault${kvs !== 1 ? 's' : ''} (secrets, certificates, keys)`);
  }

  const hasIAM = top.key_risk_factors?.some((f: string) =>
    /owner|user access|privileged role/i.test(f)
  );
  if (hasIAM) {
    lines.push('Modify IAM — grant themselves persistent access');
  }

  const sa = exposure.storage_accounts || 0;
  if (sa > 0) {
    lines.push(`Exfiltrate data from ${sa} storage account${sa !== 1 ? 's' : ''}`);
  }

  const rgs = top.resource_group_count || 0;
  if (rgs > 0 && lines.length < 5) {
    lines.push(`Reach ${rgs} resource group${rgs !== 1 ? 's' : ''}`);
  }

  return lines;
}

// ── System Assessment Builder ────────────────────────────────

function buildSystemAssessment(vm: CISOViewModel): string {
  if (vm.status === 'no_data') return '';

  const parts: string[] = [];
  const driverCount = vm.top_risk_drivers.length;
  const criticals = vm.top_risk_drivers.filter(d => d.severity === 'critical');
  const totalExposed = vm.risk_exposure.count;
  const exposurePct = vm.risk_exposure.pct;

  // Sentence 1: Overall judgment with percentage
  if (vm.status === 'critical') {
    parts.push(`${fmtPct(exposurePct)} of identities (${totalExposed} of ${vm.total_identities.toLocaleString()}) have critical or high-risk exposures across ${driverCount} risk categories — immediate remediation is required.`);
  } else if (vm.status === 'high') {
    parts.push(`${totalExposed} identities (${fmtPct(exposurePct)}) across ${driverCount} risk area${driverCount !== 1 ? 's' : ''} require attention before the next compliance review.`);
  } else if (vm.status === 'moderate') {
    parts.push(`Identity posture is acceptable with ${fmtPct(exposurePct)} exposure rate${driverCount > 0 ? `, but ${driverCount} risk area${driverCount !== 1 ? 's' : ''} remain${driverCount === 1 ? 's' : ''} open` : ''}.`);
  } else {
    parts.push(`Identity security posture is strong — ${fmtPct(exposurePct)} exposure rate across ${vm.total_identities.toLocaleString()} identities.`);
  }

  // Sentence 2: Priority recommendation with percentage
  if (criticals.length > 0) {
    const top = criticals[0];
    parts.push(`Priority: ${top.title.toLowerCase()} — ${top.count} (${fmtPct(top.pct)}) represent the highest-leverage remediation opportunity.`);
  } else if (driverCount > 0) {
    const top = vm.top_risk_drivers[0];
    parts.push(`Start with ${top.title.toLowerCase()} — ${top.count} (${fmtPct(top.pct)}) for the greatest risk reduction.`);
  }

  // Sentence 3: Blast radius context
  if (vm.blast_radius.identity_name && (vm.blast_radius.level === 'critical' || vm.blast_radius.level === 'high')) {
    parts.push(`Worst-case blast radius is ${vm.blast_radius.level}: ${vm.blast_radius.identity_name} can reach ${vm.blast_radius.consequences.length} attack surfaces if compromised.`);
  }

  return parts.join(' ');
}

// ── Business Impact Builder ─────────────────────────────────

/** Driver title → concrete business risk phrase (no jargon, no percentages). */
const DRIVER_IMPACT: Record<string, (n: number) => string> = {
  'Dormant Privileged Accounts': n => `${n} unused account${n !== 1 ? 's' : ''} retain admin access`,
  'Ghost Identities': n => `${n} disabled identit${n !== 1 ? 'ies' : 'y'} still have live access`,
  'Unowned Service Principals': n => `${n} service account${n !== 1 ? 's' : ''} operate without oversight`,
  'Excess Privilege': n => `${n} identit${n !== 1 ? 'ies' : 'y'} can modify production resources`,
  'External Guest Privilege': n => `${n} external user${n !== 1 ? 's' : ''} hold privileged access`,
};

const IMPACT_SEVERITY_ORDER: Record<string, number> = { red: 0, orange: 1, yellow: 2, green: 3 };

function buildBusinessImpact(
  vm: CISOViewModel,
  exposure: Record<string, any>,
): CISOViewModel['business_impact'] {
  const lines: CISOViewModel['business_impact'] = [];

  // 1. Sensitive data access — Key Vaults + optional storage enrichment
  const kvs = exposure.key_vaults || 0;
  const sa = exposure.storage_accounts || 0;
  if (kvs > 0 && vm.risk_exposure.count > 0) {
    const suffix = sa > 0 ? ', including production data' : '';
    lines.push({
      text: `${vm.risk_exposure.count} identit${vm.risk_exposure.count !== 1 ? 'ies' : 'y'} can access sensitive data${suffix}`,
      level: 'red',
    });
  }

  // 2. Top risk drivers → concrete business impact lines
  for (const d of vm.top_risk_drivers) {
    const fmt = DRIVER_IMPACT[d.title];
    if (fmt) {
      lines.push({
        text: fmt(d.count),
        level: d.severity === 'critical' ? 'red' : 'orange',
      });
    }
  }

  // 3. Blast radius — subscription-level resource control
  const subs = exposure.subscriptions ?? 0;
  if (vm.blast_radius.identity_name && subs > 0 && !lines.some(l => l.text.includes('production'))) {
    lines.push({
      text: `1 compromised identity could reach ${subs} subscription${subs !== 1 ? 's' : ''}`,
      level: vm.blast_radius.level === 'critical' ? 'red' : 'orange',
    });
  }

  // 4. Fallback — no drivers, no exposure
  if (lines.length === 0 && vm.total_identities > 0) {
    lines.push({
      text: `${vm.total_identities.toLocaleString()} identities monitored, no business risk detected`,
      level: 'green',
    });
  }

  // Sort: highest severity first
  lines.sort((a, b) => (IMPACT_SEVERITY_ORDER[a.level] ?? 9) - (IMPACT_SEVERITY_ORDER[b.level] ?? 9));

  return lines.slice(0, 4);
}

// ── Extended VM Builder ──────────────────────────────────────

function buildTrendHistory(trendsData: Record<string, any> | null): TrendHistory {
  if (!trendsData || !trendsData.runs || !Array.isArray(trendsData.runs)) {
    return { available: false, runs: [], posture_scores: [], direction: null, delta_narrative: 'Run a second scan to see trends.' };
  }
  const runs: Array<Record<string, any>> = trendsData.runs;
  if (runs.length < 2) {
    return { available: false, runs: [], posture_scores: [], direction: null, delta_narrative: 'Run a second scan to see trends.' };
  }
  const timestamps = runs.map((r: Record<string, any>) => r.completed_at || r.created_at || '');
  const scores = runs.map((r: Record<string, any>) => r.posture_score ?? r.agirs_score ?? 0);
  const first = scores[0];
  const last = scores[scores.length - 1];
  const diff = last - first;
  const direction: TrendHistory['direction'] = diff > 1 ? 'improving' : diff < -1 ? 'declining' : 'stable';
  const absDiff = Math.abs(diff).toFixed(1);
  const narrative = direction === 'improving'
    ? `Posture improved ${absDiff} pts over last ${scores.length} scans`
    : direction === 'declining'
    ? `Posture declined ${absDiff} pts over last ${scores.length} scans`
    : `Posture stable across last ${scores.length} scans`;
  return { available: true, runs: timestamps, posture_scores: scores, direction, delta_narrative: narrative };
}

function buildAnomalySummary(
  anomaliesData: Array<Record<string, any>> | null,
  anomalyStatsData: Record<string, any> | null,
): AnomalySummary {
  if (!anomalyStatsData && (!anomaliesData || anomaliesData.length === 0)) {
    return { available: false, unresolved: 0, by_severity: {}, top_anomalies: [], narrative: 'No anomaly data available.' };
  }
  const unresolved = anomalyStatsData?.unresolved ?? anomalyStatsData?.total ?? 0;
  const bySeverity: Record<string, number> = anomalyStatsData?.by_severity || {};
  const topAnomalies = (anomaliesData || []).slice(0, 3).map((a: Record<string, any>) => ({
    type: a.type || a.anomaly_type || 'unknown',
    severity: a.severity || 'medium',
    identity_name: a.identity_name || a.display_name || 'Unknown',
    created_at: a.created_at || '',
  }));
  const critCount = bySeverity.critical || 0;
  const highCount = bySeverity.high || 0;
  const narrative = unresolved === 0
    ? 'No unresolved anomalies detected.'
    : critCount > 0
    ? `${unresolved} unresolved anomalies including ${critCount} critical — immediate investigation required.`
    : highCount > 0
    ? `${unresolved} unresolved anomalies with ${highCount} high-severity — review recommended.`
    : `${unresolved} unresolved anomalies detected.`;
  return { available: true, unresolved, by_severity: bySeverity, top_anomalies: topAnomalies, narrative };
}

function buildRemediationProgress(remediationData: Record<string, any> | null): RemediationProgress {
  if (!remediationData) {
    return { available: false, open: 0, completed: 0, total: 0, completion_pct: 0, narrative: 'No remediation data available.' };
  }
  const open = remediationData.open ?? remediationData.pending ?? 0;
  const completed = remediationData.completed ?? remediationData.resolved ?? 0;
  const total = remediationData.total ?? (open + completed);
  const completionPct = total > 0 ? Math.round((completed / total) * 100) : 0;
  const narrative = total === 0
    ? 'No remediation items tracked.'
    : completionPct >= 80
    ? `${completionPct}% of remediations completed — strong progress.`
    : completionPct >= 50
    ? `${completionPct}% complete — ${open} actions remain open.`
    : `${open} of ${total} remediation actions remain open — prioritize top items.`;
  return { available: true, open, completed, total, completion_pct: completionPct, narrative };
}

function buildDriftSummary(driftData: Record<string, any> | null): DriftSummary {
  if (!driftData || (!driftData.total_changes && !driftData.changes)) {
    return { available: false, has_drift: false, total_changes: 0, permission_changes: 0, role_changes: 0, credential_changes: 0, narrative: 'No drift data available — run a scan to establish baseline.' };
  }
  const totalChanges = driftData.total_changes || 0;
  const permChanges = driftData.permission_changes ?? driftData.permissions_changed ?? 0;
  const roleChanges = driftData.role_changes ?? driftData.roles_changed ?? 0;
  const credChanges = driftData.credential_changes ?? driftData.credentials_changed ?? 0;
  const hasDrift = totalChanges > 0;
  const narrative = !hasDrift
    ? 'No drift detected since last scan — environment is stable.'
    : totalChanges > 10
    ? `${totalChanges} changes detected — significant drift requiring review.`
    : `${totalChanges} change${totalChanges !== 1 ? 's' : ''} detected since last scan.`;
  return { available: true, has_drift: hasDrift, total_changes: totalChanges, permission_changes: permChanges, role_changes: roleChanges, credential_changes: credChanges, narrative };
}

function buildSPNExposure(spnData: Record<string, any> | null): SPNExposure {
  if (!spnData) {
    return { available: false, total_custom: 0, critical: 0, expired_creds: 0, orphaned_privileged: 0, narrative: '' };
  }
  const totalCustom = spnData.total_custom ?? spnData.total ?? 0;
  const critical = spnData.critical ?? spnData.critical_count ?? 0;
  const expiredCreds = spnData.expired_credentials ?? spnData.expired_creds ?? 0;
  const orphaned = spnData.orphaned_privileged ?? spnData.high_blast_radius ?? 0;
  const narrative = critical > 0
    ? `${critical} critical SPNs with expired or at-risk credentials — immediate rotation needed.`
    : expiredCreds > 0
    ? `${expiredCreds} service principals have expired credentials.`
    : totalCustom > 0
    ? `${totalCustom} custom service principals monitored — no critical issues.`
    : '';
  return { available: totalCustom > 0, total_custom: totalCustom, critical, expired_creds: expiredCreds, orphaned_privileged: orphaned, narrative };
}

function buildCompositionInsights(vm: CISOViewModel): string[] {
  const insights: string[] = [];
  const cats = vm.identity_categories;
  const total = vm.total_identities;
  if (total === 0) return insights;

  const nhiCats = cats.filter(c => ['Non-Human / SPNs', 'System MSIs', 'User-Assigned MSIs'].includes(c.label));
  const nhiCount = nhiCats.reduce((s, c) => s + c.count, 0);
  const humanCat = cats.find(c => c.label === 'Human Identities');
  const guestCat = cats.find(c => c.label === 'Guest Users');

  if (nhiCount > 0 && humanCat && nhiCount > humanCat.count) {
    insights.push(`Non-human identities outnumber humans ${nhiCount} to ${humanCat.count} — machine identity governance is critical.`);
  }
  if (guestCat && guestCat.pct > 10) {
    insights.push(`${fmtPct(guestCat.pct)} of identities are external guests — review supply-chain exposure.`);
  }
  const critDrivers = vm.top_risk_drivers.filter(d => d.severity === 'critical');
  if (critDrivers.length >= 2) {
    insights.push(`${critDrivers.length} critical risk categories active simultaneously — compound risk scenario.`);
  }
  return insights;
}

/**
 * Extends the base CISO view model with data from additional API endpoints.
 * Each builder handles null gracefully — a failing endpoint never blocks the page.
 */
export function buildExtendedCISOViewModel(
  riskData: Record<string, any> | null,
  attackData: Record<string, any> | null,
  trendsData: Record<string, any> | null,
  anomaliesData: Array<Record<string, any>> | null,
  anomalyStatsData: Record<string, any> | null,
  remediationData: Record<string, any> | null,
  driftData: Record<string, any> | null,
  spnData: Record<string, any> | null,
): CISOViewModel {
  const vm = buildCISOViewModel(riskData, attackData);
  vm.trend_history = buildTrendHistory(trendsData);
  vm.anomaly_summary = buildAnomalySummary(anomaliesData, anomalyStatsData);
  vm.remediation_progress = buildRemediationProgress(remediationData);
  vm.drift_summary = buildDriftSummary(driftData);
  vm.spn_exposure = buildSPNExposure(spnData);
  vm.composition_insights = buildCompositionInsights(vm);
  return vm;
}

/**
 * Map the /api/ciso/summary response into a CISOViewModel.
 *
 * The backend provides `riskSummary` (structured risk data contract)
 * plus secondary data sources (trends, anomalies, remediation, drift, spn).
 *
 * This function delegates to buildExtendedCISOViewModel — a pure
 * transformation layer that generates display narratives and metrics.
 * No API calls, no side effects.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function mapSummaryToViewModel(response: any): CISOViewModel {
  // Debug: log raw API response (kept for SSOT tracing)
  console.log('CISO SUMMARY RESPONSE:', response);

  const data = response.data || {};
  const { riskSummary, trends, anomalies, remediation, drift, spn } = data;

  // SSOT: validate required fields from backend
  const exposureSubs = riskSummary?.exposure?.subscriptions;
  const exposureActiveSubs = riskSummary?.exposure?.active_subscriptions;
  if (exposureSubs === undefined) {
    console.error('SSOT violation: exposure.subscriptions missing from backend response');
  }
  console.log('CISO subscriptions mapping:', {
    'exposure.subscriptions': exposureSubs,
    'exposure.active_subscriptions': exposureActiveSubs,
  });

  // riskSummary is the typed risk data contract from the backend
  const riskData = riskSummary ?? null;

  const trendsData = trends?.available
    ? { count: trends.runs?.length ?? 0, runs: (trends.runs ?? []).map((date: string, i: number) => ({
        date,
        posture_score: trends.postureScores?.[i] ?? 0,
      }))}
    : null;

  const anomaliesData = anomalies?.topAnomalies ?? null;
  const anomalyStatsData = anomalies?.available
    ? { unresolved: anomalies.unresolved, by_severity: anomalies.bySeverity }
    : null;

  const remediationMapped = remediation?.available
    ? { open: remediation.open, completed: remediation.completed, total: remediation.total, completion_pct: remediation.completionPct }
    : null;

  const driftMapped = drift?.available
    ? { total_changes: drift.totalChanges, permission_changes_count: drift.permissionChanges,
        risk_changes_count: drift.roleChanges, credential_changes_count: drift.credentialChanges,
        has_drift_data: true }
    : null;

  const spnMapped = spn?.available
    ? { custom: spn.totalCustom, critical: spn.critical, expired_credentials: spn.expiredCreds,
        orphaned_privileged: spn.orphanedPrivileged }
    : null;

  const vm = buildExtendedCISOViewModel(
    riskData, null, trendsData,
    anomaliesData, anomalyStatsData,
    remediationMapped, driftMapped, spnMapped,
  );

  // ── SSOT overrides from envelope (these fields come from the envelope,
  //    not from attackData which is null in the /api/ciso/summary path) ──
  vm.coverage_pct = response.coverage ?? 0;

  // last_updated: prefer envelope lastUpdated → riskSummary computed_at → keep default
  // Guard: reject empty strings, Python str(None)="None", and "null"
  const INVALID_TIMESTAMPS = new Set(['', 'None', 'null', 'undefined']);
  const envelopeLastUpdated = response.lastUpdated;
  const riskComputedAt = riskSummary?.computed_at;
  const lastScanRaw = (envelopeLastUpdated && !INVALID_TIMESTAMPS.has(envelopeLastUpdated))
    ? envelopeLastUpdated
    : (riskComputedAt && !INVALID_TIMESTAMPS.has(riskComputedAt))
      ? riskComputedAt
      : null;
  console.log('CISO lastUpdated resolution:', {
    envelopeLastUpdated, riskComputedAt, lastScanRaw,
  });
  if (lastScanRaw) {
    const parsed = formatRelativeTime(lastScanRaw);
    if (parsed !== 'Never') {
      vm.last_updated = parsed;
    } else {
      console.warn('CISO: formatRelativeTime returned "Never" for raw:', lastScanRaw);
    }
  }

  // data_confidence: envelope confidence is authoritative (computed from usable sources)
  const envConfidence = response.confidence;
  if (envConfidence === 'high' || envConfidence === 'medium' || envConfidence === 'low') {
    vm.data_confidence = envConfidence;
    vm.confidence_reason = buildConfidenceReason(vm);
  }

  return vm;
}
