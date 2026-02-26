import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { useConnection } from '../contexts/ConnectionContext';

// ═══════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════

interface DrilldownItem { label: string; impact: 'critical' | 'high' | 'medium' | 'low' }
interface PillarData { name: string; score: number; weight: number; detail: string; drilldown: DrilldownItem[] }
interface RiskDriver { label: string; impact: 'critical' | 'high' | 'medium' | 'low'; pillar: string }
interface BlastRadius { identities: number; subscriptions: number; workloads: number }
interface Remediation {
  rank: number; action: string; description: string; gain: number;
  complexity: 'LOW' | 'MEDIUM' | 'HIGH'; affectedIds: number; confidence: number;
  estimatedDays: number; automation: 'full' | 'partial' | 'manual';
  blastRadius: BlastRadius; rollbackSafety: 'safe' | 'requires-validation' | 'irreversible';
  impactsProduction: boolean;
  type: 'identity-remediation' | 'system-action' | 'configuration';
}
interface ComplianceControl {
  controlId: string; name: string;
  status: 'pass' | 'warn' | 'fail';
  severity: 'critical' | 'high' | 'medium' | 'low';
  metric: string; value: number; passThreshold: string;
  detail: string; drilldownUrl: string | null; weight: number;
  evidenceIdentities: Array<{ id: number; identity_id: string; display_name: string; risk_level: string; risk_score: number; identity_category: string; reason: string }>;
  evidenceCount: number;
}
interface Framework {
  name: string; passed: number; total: number; pct: number;
  failingIdentities: number; controlMappingSource: string;
  coverageTrend30d: number | null;
  controls: ComplianceControl[];
  key: string;
  category: string;
}
interface ScoringMethodology { url: string; label: string; summary: string }
interface GovMetric { label: string; value: number; target: number; icon: string; trend30d: number | null; configured: boolean }
interface PolicyGap { label: string; count: number; severity: 'critical' | 'high' | 'medium' | 'low' }
interface TrendRow { label: string; previous: number; current: number; direction: 'up' | 'down' | 'same' }
interface AffectedWorkload {
  name: string; type: string; region: string; exposedIdentities: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
}
interface ComponentAvg { name: string; score: number; max: number }
interface SystemAction { id: string; label: string; status: 'pending' | 'completed' | 'in-progress' | 'failed'; description: string }
interface ScoringContent {
  overview: string; scoreDirection: string;
  pillars: { name: string; weight: number; description: string }[];
  compositeFormula: string;
  tierThresholds: { tier: string; range: string; description: string }[];
}

type Nav = (path: string) => void;

// Navigation target mapping for governance metrics
const GOV_NAV: Record<string, string> = {
  'Ownership Coverage': '/service-accounts',
  'PIM Coverage': '/identities',
  'Privileged Under Review': '/access-reviews',
  'Access Reviews Done': '/access-reviews',
};

// Navigation target mapping for KPI cards
const KPI_NAV: Record<string, string> = {
  'Privileged NHIs': '/workload-identities',
  'Dormant Privileged': '/identities?activity_status=stale',
  'Subscription Access': '/identities',
  'RBAC Modifiers': '/identities',
};

// Navigation target mapping for risk movement rows
const MOVE_NAV: Record<string, string> = {
  'Critical Identities': '/identities?risk_level=critical',
  'High-Risk Identities': '/identities?risk_level=high',
  'Total Identities': '/identities',
  'New Identities': '/identities',
  'Removed': '/identities',
};

// Navigation target mapping for pillar scores
const PILLAR_NAV: Record<string, string> = {
  'Effective Privilege': '/identities?risk_level=critical',
  'Credential Risk': '/spns',
  'Trust & Federation': '/identities?identity_category=guest',
  'Usage Dormancy': '/identities?activity_status=stale',
  'Ownership Governance': '/service-accounts',
  'External Exposure': '/identities',
};

// Navigation target mapping for workload exposure metrics
const WORKLOAD_NAV: Record<string, string> = {
  'Avg Score': '/workload-identities',
  'Can Escalate': '/identities?risk_level=critical',
  'Orphaned': '/service-accounts',
  'Zombies': '/identities?activity_status=stale',
  'Cross-Sub': '/identities',
  'Tenant Scope': '/identities',
};

// Navigation target mapping for lifecycle states
const LIFECYCLE_NAV: Record<string, string> = {
  'Active': '/identities?activity_status=active',
  'Stale': '/identities?activity_status=stale',
  'Dormant': '/identities?activity_status=inactive',
  'Blind': '/workload-identities',
};

// Navigation target mapping for policy gaps
const POLICY_GAP_NAV: Record<string, string> = {
  'Privilege outside PIM': '/identities?risk_level=critical',
};

// Filter to identity_category mapping for header drill
const FILTER_NAV: Record<string, string> = {
  All: '/identities',
  Users: '/identities?identity_category=human_user',
  SPNs: '/identities?identity_category=service_principal',
  Managed: '/identities?identity_category=managed_identity_system',
  Workload: '/workload-identities',
};

interface TenantData {
  tenant: {
    id: string; name: string; cloud: string; subscriptions: number;
    lastScan: string; scanDuration: number; scanCompleteness: number;
    scanConfidence: string; sources: string[]; confidenceModelBasis: string;
    scanCoverage: number; dataCompleteness: number; lastUpdatedAgo: string;
    isolationGuarantee: string;
    organizationName: string;
    organizationLogo: string | null;
  };
  scoringMethodology: ScoringMethodology;
  scoringContent: ScoringContent;
  executiveSummary: {
    riskNarrative: string;
    businessExposure: { identities: number; subscriptions: number; productionWorkloads: number; totalProductionWorkloads: number };
  };
  identities: {
    total: number; critical: number; high: number; medium: number; low: number;
    byType: { users: number; servicePrincipals: number; managedIdentities: number; workloadIdentities: number; crossTenant: number };
    movement: { previousTotal: number; newIdentities: number; removedIdentities: number };
  };
  riskScore: {
    current: number; grade: string; tier: string; previous30d: number; delta30d: number;
    industryAvg: number; target: number; potentialGain: number;
    projectedNoAction: number; projectedRemediated: number;
    history: { day: number; score: number }[];
  };
  pillars: PillarData[];
  topRiskDrivers: RiskDriver[];
  kpis: {
    privilegedNHIs: { count: number; description: string };
    dormantPrivileged: { count: number; description: string };
    subscriptionAccess: { count: number; description: string };
    rbacModifiers: { count: number; description: string };
  };
  workloadExposure: {
    avgScore: number; canEscalate: number; orphaned: number;
    exposureDistribution: { critical: number; high: number; medium: number; low: number };
    componentAverages: ComponentAvg[];
    lifecycleState: { active: number; stale: number; dormant: number; blind: number };
    blindTooltip: string; zombies: number; crossSub: number; tenantScope: number;
    topAffectedWorkloads: AffectedWorkload[];
  };
  remediations: Remediation[];
  systemActions: SystemAction[];
  compliance: {
    frameworks: Record<string, Framework[]>;
    controlMaturity: { preventive: number; detective: number; compensating: number; missing: number };
    remediationProgress: number; saGovernance: number;
  };
  governance: {
    metrics: GovMetric[];
    policyGaps: { preventiveFailures: PolicyGap[]; operationalGaps: PolicyGap[] };
    effectivenessScore: number; effectivenessTooltip: string;
    effectivenessConfigured: boolean;
    maturityLevel: string;
  };
  trends: {
    movement30d: TrendRow[];
    noActionImpact: string[];
    estimatedBreachImpact: string; remediatedBreachImpact: string;
    remediatedConsequences: string[];
    biggestContributor: { label: string; delta: string; pillar: string };
  };
}

// ═══════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

function getTier(score: number): string {
  if (score <= 40) return 'Critical';
  if (score <= 60) return 'Elevated';
  if (score <= 80) return 'Controlled';
  return 'Resilient';
}
function getGrade(score: number): string {
  if (score <= 20) return 'F';
  if (score <= 40) return 'D';
  if (score <= 60) return 'C';
  if (score <= 80) return 'B';
  return 'A';
}
function getTierColor(tier: string): string {
  const m: Record<string, string> = { Critical: '#ff4444', Elevated: '#ff8c00', Controlled: '#eab308', Resilient: '#22c55e' };
  return m[tier] || '#64748b';
}
function getTierBg(tier: string): string {
  const m: Record<string, string> = { Critical: 'rgba(255,68,68,0.15)', Elevated: 'rgba(255,140,0,0.15)', Controlled: 'rgba(234,179,8,0.15)', Resilient: 'rgba(34,197,94,0.15)' };
  return m[tier] || 'rgba(255,255,255,0.05)';
}
function getPillarColor(score: number): string {
  if (score >= 80) return '#ff4444';
  if (score >= 50) return '#ff8c00';
  if (score >= 20) return '#eab308';
  return '#22c55e';
}
function getSeverityColor(severity: string): string {
  const m: Record<string, string> = { critical: '#ff4444', high: '#ff8c00', medium: '#eab308', low: '#22c55e' };
  return m[severity] || '#64748b';
}
function getAutomationConfig(level: string) {
  const m: Record<string, { label: string; color: string }> = {
    full: { label: 'Auto', color: '#22c55e' },
    partial: { label: 'Semi-Auto', color: '#eab308' },
    manual: { label: 'Manual', color: '#ff8c00' },
  };
  return m[level] || m.manual;
}
function getRollbackConfig(safety: string) {
  const m: Record<string, { label: string; color: string; icon: string }> = {
    safe: { label: 'Safe to rollback', color: '#22c55e', icon: '\u21A9' },
    'requires-validation': { label: 'Requires manual validation', color: '#eab308', icon: '\u26A0' },
    irreversible: { label: 'Cannot be undone', color: '#ff4444', icon: '\u2715' },
  };
  return m[safety] || m['requires-validation'];
}
function getRiskPerDay(gain: number, days: number): string {
  if (!days || days === 0) return '\u2014';
  return (gain / days).toFixed(1);
}
function formatTrend(value: number | null) {
  if (value === null || value === undefined) return { text: 'Initial assessment', color: P.textDim };
  if (value === 0) return { text: '\u2014 unchanged', color: P.textDim };
  if (value > 0) return { text: `\u2191 +${value}%`, color: '#22c55e' };
  return { text: `\u2193 ${value}%`, color: '#ff4444' };
}
function formatDelta(value: number): string {
  if (value > 0) return `+${value}`;
  return `${value}`;
}
function getMaturityLevel(score: number, configured = true): string {
  if (!configured) return 'Not Assessed';
  if (score <= 20) return 'Ad-hoc';
  if (score <= 40) return 'Developing';
  if (score <= 60) return 'Operational';
  if (score <= 80) return 'Managed';
  return 'Optimized';
}
function getMaturityColor(level: string): string {
  const m: Record<string, string> = { 'Ad-hoc': '#ff4444', Developing: '#ff8c00', Operational: '#eab308', Managed: '#22c55e', Optimized: '#3b82f6', 'Not Assessed': '#475569' };
  return m[level] || '#64748b';
}
function getProductionExposurePct(affected: number, total: number): number {
  if (!total || total === 0) return 0;
  return Math.round((affected / total) * 100);
}
function getCompletenessColor(pct: number): string {
  if (pct >= 95) return '#22c55e';
  if (pct >= 80) return '#eab308';
  return '#ff4444';
}
function getTimeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

const F = { ui: '"Inter", -apple-system, sans-serif', data: '"JetBrains Mono", monospace' };

const P = {
  bgPage: 'var(--ciso-bg-page)',
  bgCard: 'var(--ciso-bg-card)',
  bgCardMuted: 'var(--ciso-bg-card-muted)',
  borderCard: 'var(--ciso-border-card)',
  bgHover: 'var(--ciso-bg-hover)',
  bgSubtle: 'var(--ciso-bg-subtle)',
  bgActive: 'var(--ciso-bg-active)',
  track: 'var(--ciso-track)',
  divider: 'var(--ciso-divider)',
  overlay: 'var(--ciso-overlay)',
  overlayStrong: 'var(--ciso-overlay-strong)',
  backdrop: 'var(--ciso-backdrop)',
  glow: 'var(--ciso-glow)',
  panelBg: 'var(--ciso-panel-bg)',
  btnGradient: 'var(--ciso-btn-gradient)',
  textBright: 'var(--ciso-text-bright)',
  textLight: 'var(--ciso-text-light)',
  textSub: 'var(--ciso-text-sub)',
  textMuted: 'var(--ciso-text-muted)',
  textDim: 'var(--ciso-text-dim)',
  textFaint: 'var(--ciso-text-faint)',
  accentIndigo: 'var(--ciso-accent-indigo)',
  accentStrong: 'var(--ciso-accent-strong)',
  accentIndigoBg: 'var(--ciso-accent-indigo-bg)',
  accentIndigoSubtle: 'var(--ciso-accent-indigo-subtle)',
  accentIndigoFaint: 'var(--ciso-accent-indigo-faint)',
  tooltipBg: 'var(--ciso-tooltip-bg)',
  tooltipBorder: 'var(--ciso-tooltip-border)',
};

// ═══════════════════════════════════════════════════════════════════════
// DATA FETCHING & TRANSFORMATION
// ═══════════════════════════════════════════════════════════════════════

const PILLAR_NAMES: Record<string, string> = {
  effective_privilege: 'Effective Privilege',
  credential_risk: 'Credential Risk',
  trust_federation: 'Trust & Federation',
  usage_dormancy: 'Usage Dormancy',
  ownership_governance: 'Ownership Governance',
  external_exposure: 'External Exposure',
};
const PILLAR_ORDER = ['effective_privilege', 'credential_risk', 'trust_federation', 'usage_dormancy', 'ownership_governance', 'external_exposure'];

function detailToString(key: string, detail: Record<string, number>): string {
  switch (key) {
    case 'effective_privilege': return `${detail.t0 || 0} t0`;
    case 'credential_risk': return `${detail.expired || 0} expired`;
    case 'trust_federation': return `${detail.federated || detail.guests || 0} federated`;
    case 'usage_dormancy': return `${detail.dormant || 0} dormant`;
    case 'ownership_governance': return `${detail.total_spns || detail.unowned_spns || 0} total spns`;
    case 'external_exposure': return `${detail.tenant_scope || 0} tenant scope`;
    default: return '';
  }
}

function detailToDrilldown(key: string, detail: Record<string, number>): DrilldownItem[] {
  const items: DrilldownItem[] = [];
  switch (key) {
    case 'effective_privilege':
      if (detail.t0) items.push({ label: `${detail.t0} identities with Tier-0 role assignments`, impact: 'critical' });
      if (detail.t0t1 && detail.t0t1 > (detail.t0 || 0)) items.push({ label: `${detail.t0t1 - (detail.t0 || 0)} identities with Tier-1 roles`, impact: 'high' });
      break;
    case 'credential_risk':
      if (detail.expired) items.push({ label: `${detail.expired} expired credentials still active`, impact: 'high' });
      if (detail.expiring) items.push({ label: `${detail.expiring} credentials expiring within 30 days`, impact: 'medium' });
      if (!detail.expired && !detail.expiring) items.push({ label: 'No expired credentials detected', impact: 'low' });
      break;
    case 'trust_federation':
      if (detail.guest_with_roles) items.push({ label: `${detail.guest_with_roles} guest identities with privileged roles`, impact: 'high' });
      if (detail.federated) items.push({ label: `${detail.federated} externally federated identities`, impact: 'medium' });
      if (!detail.guest_with_roles && !detail.federated) items.push({ label: 'No external federation configured', impact: 'low' });
      break;
    case 'usage_dormancy':
      if (detail.dormant) items.push({ label: `${detail.dormant} identities inactive >30 days with active roles`, impact: 'high' });
      break;
    case 'ownership_governance':
      if (detail.unowned_spns) items.push({ label: `${detail.unowned_spns} orphaned SPNs with no assigned owner`, impact: 'high' });
      break;
    case 'external_exposure':
      if (detail.tenant_scope) items.push({ label: `${detail.tenant_scope} identities with tenant-wide scope`, impact: 'medium' });
      break;
  }
  return items.length ? items : [{ label: 'No significant issues', impact: 'low' }];
}

async function fetchJson(url: string) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

async function fetchTenantData(wc: (u: string) => string = u => u): Promise<TenantData> {
  const [as, stats, comp, trends, posture, remed, idSummary, settings] = await Promise.all([
    fetchJson(wc('/api/overview/attack-surface-score')).catch(() => null),
    fetchJson(wc('/api/stats')).catch(() => null),
    fetchJson(wc('/api/compliance/intelligence')).catch(() => null),
    fetchJson(wc('/api/trends?limit=30')).catch(() => null),
    fetchJson(wc('/api/dashboard/posture')).catch(() => null),
    fetchJson(wc('/api/remediation-summary')).catch(() => null),
    fetchJson(wc('/api/identity-summary')).catch(() => null),
    fetchJson(wc('/api/settings')).catch(() => null),
  ]);

  const lr = stats?.latest_run || {};
  const pr = stats?.previous_run || {};
  const gov = as?.governance || {};
  const di = as?.data_integrity || {};
  const we = as?.workload_exposure || {};
  const ao = as?.attack_opportunities || {};
  const nhi = as?.nhi_breakdown || {};
  const monitored = idSummary?.monitored_resources || {};

  const totalIds = lr.total_identities || as?.total_identities || 0;
  const critCount = lr.critical_count || 0;
  const highCount = lr.high_count || 0;
  const medCount = lr.medium_count || 0;
  const lowCount = Math.max(0, totalIds - critCount - highCount - medCount);

  // Single source of truth: 6-pillar attack surface score (higher = worse risk).
  // Invert to posture (higher = better). If attack-surface API unavailable, derive
  // from pillar data or fall back to posture endpoint (capped to avoid inflated scores).
  const postureScore = (() => {
    if (as?.score != null) return Math.round((100 - as.score) * 10) / 10;
    // Fallback: posture endpoint uses simple (total - risky) / total formula which inflates.
    // Cap at 75 to avoid showing "Resilient" when attack surface data is missing.
    const fallback = posture?.posture_score;
    if (fallback != null) return Math.min(fallback, 75);
    return 50; // Unknown state
  })();
  const tier = getTier(postureScore);
  const grade = getGrade(postureScore);
  const prevPosture = posture?.previous_posture_score != null
    ? Math.min(posture.previous_posture_score, as?.score != null ? 100 : 75)
    : (postureScore - 2);
  const delta30d = Math.round((postureScore - prevPosture) * 10) / 10;

  const pillars: PillarData[] = PILLAR_ORDER.map(k => {
    const p = as?.pillars?.[k] || { score: 0, weight: 10, detail: {} };
    return {
      name: PILLAR_NAMES[k] || k,
      score: p.score || 0,
      weight: p.weight || 10,
      detail: detailToString(k, p.detail || {}),
      drilldown: detailToDrilldown(k, p.detail || {}),
    };
  });

  const potentialGain = remed?.potential_gain ?? Math.round(pillars.reduce((s, p) => s + (p.score > 50 ? p.weight * 0.3 : 0), 0) * 10) / 10;

  const history: { day: number; score: number }[] = [];
  if (Array.isArray(trends)) {
    trends.slice(-30).forEach((t: any, i: number) => {
      history.push({ day: i + 1, score: t.posture_score ?? (100 - (t.avg_risk_score || 50)) });
    });
  }
  if (!history.length) {
    for (let i = 1; i <= 7; i++) history.push({ day: i * 5 - 4, score: postureScore - (7 - i) * 1.2 });
    history.push({ day: 30, score: postureScore });
  }

  const topDrivers: RiskDriver[] = [];
  const sortedPillars = [...pillars].sort((a, b) => b.score - a.score);
  for (const p of sortedPillars.slice(0, 5)) {
    if (p.score > 10) {
      const imp: RiskDriver['impact'] = p.score >= 80 ? 'critical' : p.score >= 50 ? 'high' : p.score >= 20 ? 'medium' : 'low';
      topDrivers.push({ label: `${p.detail} — ${p.name} at ${p.score}%`, impact: imp, pillar: p.name });
    }
  }
  if (ao.privileged_nhi_count) topDrivers.push({ label: `${ao.privileged_nhi_count} privileged non-human identities`, impact: 'medium', pillar: 'Privilege' });
  while (topDrivers.length < 5) topDrivers.push({ label: 'No additional risk drivers', impact: 'low', pillar: '' });

  const remedList: Remediation[] = [];
  const remedItems = remed?.items || remed?.remediations || [];
  if (Array.isArray(remedItems) && remedItems.length > 0) {
    remedItems.forEach((r: any, i: number) => {
      const comp = r.complexity || (r.gain > 5 ? 'MEDIUM' : 'LOW');
      const rType = r.type || 'identity-remediation';
      remedList.push({
        rank: i + 1, action: r.action || r.label || `Action ${i + 1}`,
        description: r.description || '', gain: r.gain || r.score_impact || 0,
        complexity: comp, affectedIds: r.affected_ids || r.affectedIds || 0,
        confidence: r.confidence || 85, estimatedDays: r.estimated_days || (comp === 'LOW' ? 3 : comp === 'MEDIUM' ? 7 : 14),
        automation: r.automation || (comp === 'LOW' ? 'full' : comp === 'MEDIUM' ? 'partial' : 'manual'),
        blastRadius: r.blast_radius || { identities: r.affected_ids || 0, subscriptions: 1, workloads: 0 },
        rollbackSafety: r.rollback_safety || (comp === 'LOW' ? 'safe' : comp === 'HIGH' ? 'irreversible' : 'requires-validation'),
        impactsProduction: r.impacts_production ?? (r.blast_radius?.workloads > 0),
        type: rType === 'system-action' || rType === 'configuration' ? rType : 'identity-remediation',
      });
    });
  }

  // Derive remediation items from pillar data when API doesn't return items
  if (!remedList.length && as?.pillars) {
    const pillarRemediations: { action: string; description: string; gain: number; complexity: 'LOW' | 'MEDIUM' | 'HIGH'; affectedIds: number; nav: string }[] = [];
    const pils = as.pillars;
    if (pils.effective_privilege?.score > 15) {
      const d = pils.effective_privilege.detail || {};
      pillarRemediations.push({
        action: 'Reduce over-privileged identities',
        description: `${d.t0t1 || 0} identities hold T0/T1 privileges — review and remove unnecessary Global Admin, Owner, and Contributor roles.`,
        gain: Math.round(pils.effective_privilege.score * 0.3 * (pils.effective_privilege.weight || 30) / 10),
        complexity: pils.effective_privilege.score > 60 ? 'HIGH' : 'MEDIUM',
        affectedIds: d.t0t1 || 0, nav: '/identities?risk_level=critical',
      });
    }
    if (pils.credential_risk?.score > 15) {
      const d = pils.credential_risk.detail || {};
      const badCreds = (d.expired || 0) + (d.expiring || 0);
      pillarRemediations.push({
        action: 'Rotate expired & expiring credentials',
        description: `${badCreds} credentials are expired or expiring within 30 days — rotate secrets and certificates immediately.`,
        gain: Math.round(pils.credential_risk.score * 0.3 * (pils.credential_risk.weight || 20) / 10),
        complexity: 'LOW',
        affectedIds: badCreds, nav: '/workload-identities',
      });
    }
    if (pils.usage_dormancy?.score > 15) {
      const d = pils.usage_dormancy.detail || {};
      pillarRemediations.push({
        action: 'Disable dormant identities',
        description: `${d.dormant || 0} identities are stale or never used — disable or remove to reduce attack surface.`,
        gain: Math.round(pils.usage_dormancy.score * 0.3 * (pils.usage_dormancy.weight || 10) / 10),
        complexity: 'LOW',
        affectedIds: d.dormant || 0, nav: '/identities?activity_status=stale',
      });
    }
    if (pils.ownership_governance?.score > 15) {
      const d = pils.ownership_governance.detail || {};
      pillarRemediations.push({
        action: 'Assign owners to unowned service principals',
        description: `${d.unowned_spns || 0} of ${d.total_spns || 0} service principals lack owners — assign accountability for each.`,
        gain: Math.round(pils.ownership_governance.score * 0.3 * (pils.ownership_governance.weight || 10) / 10),
        complexity: 'LOW',
        affectedIds: d.unowned_spns || 0, nav: '/workload-identities',
      });
    }
    if (pils.trust_federation?.score > 15) {
      const d = pils.trust_federation.detail || {};
      pillarRemediations.push({
        action: 'Review guest & external privileged access',
        description: `${d.guest_with_roles || 0} guest identities hold privileged roles — audit and restrict external access.`,
        gain: Math.round(pils.trust_federation.score * 0.3 * (pils.trust_federation.weight || 20) / 10),
        complexity: 'MEDIUM',
        affectedIds: d.guest_with_roles || 0, nav: '/identities?identity_category=guest',
      });
    }
    if (pils.external_exposure?.score > 15) {
      const d = pils.external_exposure.detail || {};
      pillarRemediations.push({
        action: 'Scope down tenant-wide permissions',
        description: `${d.tenant_scope || 0} identities have tenant-wide scope — apply least-privilege at subscription or resource group level.`,
        gain: Math.round(pils.external_exposure.score * 0.3 * (pils.external_exposure.weight || 10) / 10),
        complexity: 'HIGH',
        affectedIds: d.tenant_scope || 0, nav: '/identities',
      });
    }
    // Sort by gain desc and assign ranks
    pillarRemediations.sort((a, b) => b.gain - a.gain);
    pillarRemediations.forEach((pr, i) => {
      remedList.push({
        rank: i + 1, action: pr.action, description: pr.description, gain: pr.gain,
        complexity: pr.complexity, affectedIds: pr.affectedIds, confidence: 90,
        estimatedDays: pr.complexity === 'LOW' ? 3 : pr.complexity === 'MEDIUM' ? 7 : 14,
        automation: pr.complexity === 'LOW' ? 'full' : pr.complexity === 'MEDIUM' ? 'partial' : 'manual',
        blastRadius: { identities: pr.affectedIds, subscriptions: 1, workloads: 0 },
        rollbackSafety: pr.complexity === 'LOW' ? 'safe' : pr.complexity === 'HIGH' ? 'irreversible' : 'requires-validation',
        impactsProduction: false, type: 'identity-remediation',
      });
    });
  }

  // System actions — always present; "Run Discovery Scan" is a system action, never a ranked remediation
  const systemActions: SystemAction[] = [
    { id: 'run-scan', label: 'Run Discovery Scan', status: lr.completed_at ? 'completed' : 'pending', description: lr.completed_at ? `Last scan: ${getTimeAgo(lr.completed_at)}` : 'No scan completed yet' },
  ];

  const compFrameworks: Record<string, Framework[]> = {};
  if (comp?.frameworks) {
    Object.entries(comp.frameworks as Record<string, any>).forEach(([fwKey, fw]) => {
      const cat = fw.category === 'privacy' ? 'Privacy' : fw.tier === 'core' ? 'Core Governance' : fw.tier === 'benchmark' ? 'Benchmark' : 'Industry';
      if (!compFrameworks[cat]) compFrameworks[cat] = [];
      const passCount = fw.pass_count || 0;
      const totalCount = fw.total_controls || 1;
      const controls: ComplianceControl[] = (fw.controls || []).map((c: any) => ({
        controlId: c.control_id || '', name: c.name || '',
        status: c.status || 'pass', severity: c.severity || 'medium',
        metric: c.metric || '', value: c.value ?? 0, passThreshold: c.pass_threshold || '',
        detail: c.detail || '', drilldownUrl: c.drilldown_url || null, weight: c.weight || 5,
        evidenceIdentities: c.evidence_identities || [], evidenceCount: c.evidence_count || 0,
      }));
      compFrameworks[cat].push({
        name: fw.name || fw.short_name || 'Unknown',
        passed: passCount, total: totalCount,
        pct: Math.round((passCount / totalCount) * 100),
        failingIdentities: fw.affected_entities || fw.failing_identities || 0,
        controlMappingSource: fw.scope_label || fw.control_mapping_source || `Mapped to: identity access controls`,
        coverageTrend30d: fw.coverage_trend_30d ?? null,
        controls, key: fwKey, category: cat,
      });
    });
  }
  if (!Object.keys(compFrameworks).length) {
    compFrameworks['Core Governance'] = [{ name: 'No data', passed: 0, total: 1, pct: 0, failingIdentities: 0, controlMappingSource: 'Run a discovery scan', coverageTrend30d: null, controls: [], key: 'none', category: 'Core Governance' }];
  }

  const govMetrics: GovMetric[] = [
    { label: 'Ownership Coverage', value: Math.round(gov.ownership_coverage_pct || 0), target: 80, icon: '\uD83D\uDC64', trend30d: null, configured: gov.ownership_coverage_pct != null && gov.ownership_coverage_pct > 0 },
    { label: 'PIM Coverage', value: Math.round(gov.pim_adoption_pct || 0), target: 90, icon: '\uD83D\uDD10', trend30d: null, configured: gov.pim_adoption_pct != null && gov.pim_adoption_pct > 0 },
    { label: 'Privileged Under Review', value: Math.round(gov.privileged_under_review_pct || 0), target: 100, icon: '\uD83D\uDCCB', trend30d: null, configured: gov.privileged_under_review_pct != null && gov.privileged_under_review_pct > 0 },
    { label: 'Access Reviews Done', value: Math.round(gov.access_reviews_done ? Math.min(100, (gov.access_reviews_done / Math.max(1, totalIds)) * 100) : 0), target: 95, icon: '\u2713', trend30d: null, configured: gov.access_reviews_done != null && gov.access_reviews_done > 0 },
  ];
  const effectivenessConfigured = govMetrics.some(m => m.configured);

  const policyGaps: { preventiveFailures: PolicyGap[]; operationalGaps: PolicyGap[] } = {
    preventiveFailures: [], operationalGaps: [],
  };
  if (gov.pim_adoption_pct != null && gov.pim_adoption_pct < 50) policyGaps.preventiveFailures.push({ label: 'Privilege outside PIM', count: ao.privileged_nhi_count || 0, severity: 'critical' });
  if (gov.ownership_coverage_pct != null && gov.ownership_coverage_pct < 50) policyGaps.operationalGaps.push({ label: `Ownership coverage at ${Math.round(gov.ownership_coverage_pct)}%`, count: we.flags?.orphaned || 0, severity: 'high' });
  if (ao.dormant_privileged_count) policyGaps.operationalGaps.push({ label: 'Dormant privileged accounts active', count: ao.dormant_privileged_count, severity: 'medium' });

  const effScore = Math.round((govMetrics.reduce((s, m) => s + m.value, 0) / govMetrics.length));

  const lifecycleDist = we.lifecycle_distribution || {};
  const blindCount = lifecycleDist.blind || 0;
  // Source of truth: /api/identity-summary → monitored_resources.azure.subscriptions
  const azureSubs = monitored.azure?.subscriptions || 0;
  const awsAccounts = monitored.aws?.accounts || 0;
  const gcpProjects = monitored.gcp?.projects || 0;
  const subs = azureSubs + awsAccounts + gcpProjects || 0;

  return {
    tenant: {
      id: di.tenant_id || 'unknown', name: di.tenant_name || 'Tenant',
      cloud: [azureSubs > 0 && 'Azure', awsAccounts > 0 && 'AWS', gcpProjects > 0 && 'GCP'].filter(Boolean).join(' + ') || 'Azure',
      subscriptions: subs,
      lastScan: di.last_scan || lr.completed_at || new Date().toISOString(),
      scanDuration: di.scan_duration_seconds || 0, scanCompleteness: di.data_completeness_pct || 100,
      scanConfidence: di.confidence || 'Medium', sources: ['Azure RBAC', 'Entra ID', 'Graph API'],
      confidenceModelBasis: `Based on ${di.confidence || 'trend'} confidence — ${di.data_completeness_pct || 100}% data completeness`,
      scanCoverage: subs > 0 ? Math.round((di.data_completeness_pct || 100)) : 0,
      dataCompleteness: Math.round(di.data_completeness_pct || 100),
      lastUpdatedAgo: di.last_scan ? getTimeAgo(di.last_scan) : 'unknown',
      isolationGuarantee: 'Isolated dataset \u2022 No cross-tenant visibility',
      organizationName: settings?.settings?.org_name || di.organization_name || di.tenant_name || 'Tenant',
      organizationLogo: di.organization_logo || null,
    },
    scoringMethodology: {
      url: 'https://docs.auditgraph.ai/scoring-methodology',
      label: 'View scoring methodology',
      summary: '6-pillar weighted model: Effective Privilege (30%), Credential Risk (20%), Trust & Federation (20%), Usage Dormancy (10%), Ownership Governance (10%), External Exposure (10%). Each pillar scored 0-100 where higher = more risk.',
    },
    scoringContent: {
      overview: 'AuditGraph computes a composite Identity Attack Surface Score from six weighted security pillars. Each pillar is scored 0\u2013100 where higher values indicate greater risk exposure.',
      scoreDirection: 'Score scale: 0 = no risk \u00B7 100 = maximum risk',
      pillars: [
        { name: 'Effective Privilege', weight: 30, description: 'Measures tier-0/tier-1 role density, standing admin access, and blast radius of privileged identities.' },
        { name: 'Credential Risk', weight: 20, description: 'Tracks expired credentials, soon-to-expire secrets, and rotation compliance across SPNs and app registrations.' },
        { name: 'Trust & Federation', weight: 20, description: 'Evaluates guest identities with privileged roles, external federation configurations, and cross-tenant trust chains.' },
        { name: 'Usage Dormancy', weight: 10, description: 'Identifies identities inactive >30 days that retain active role assignments \u2014 zombie accounts with live access.' },
        { name: 'Ownership Governance', weight: 10, description: 'Measures orphaned SPN coverage, attestation freshness, and ownership assignment completeness.' },
        { name: 'External Exposure', weight: 10, description: 'Detects identities with tenant-wide scope, multi-subscription access at Contributor+, and public-facing service principals.' },
      ],
      compositeFormula: 'Composite = \u03A3(pillar_score \u00D7 pillar_weight) / 100',
      tierThresholds: [
        { tier: 'Resilient', range: '81\u2013100', description: 'Strong posture across all pillars. Minimal attack surface.' },
        { tier: 'Controlled', range: '61\u201380', description: 'Acceptable posture with identified improvement areas.' },
        { tier: 'Elevated', range: '41\u201360', description: 'Significant gaps requiring remediation within 30 days.' },
        { tier: 'Critical', range: '0\u201340', description: 'Immediate action required. High blast radius exposure.' },
      ],
    },
    executiveSummary: {
      riskNarrative: as?.ciso_summary || `Identity posture is ${tier.toLowerCase()} with a score of ${postureScore.toFixed(1)}/100.`,
      businessExposure: { identities: totalIds, subscriptions: subs, productionWorkloads: we.total || 0, totalProductionWorkloads: we.total || 0 },
    },
    identities: {
      total: totalIds, critical: critCount, high: highCount, medium: medCount, low: lowCount,
      byType: {
        users: idSummary?.categories?.human_user?.total ?? nhi.human ?? 0,
        servicePrincipals: idSummary?.categories?.service_principal?.total ?? nhi.service_principal ?? 0,
        managedIdentities: (idSummary?.categories?.managed_identity_system?.total ?? nhi.managed_identity_system ?? 0) + (idSummary?.categories?.managed_identity_user?.total ?? nhi.managed_identity_user ?? 0),
        workloadIdentities: nhi.nhi_total || 0,
        crossTenant: idSummary?.categories?.guest?.total ?? nhi.guest ?? 0,
      },
      movement: { previousTotal: pr.total_identities || 0, newIdentities: lr.new_identities || 0, removedIdentities: lr.removed_identities || 0 },
    },
    riskScore: (() => {
      const remedGain = remedList.filter(r => r.type === 'identity-remediation').reduce((s, r) => s + r.gain, 0);
      const finalGain = remedGain > 0 ? remedGain : potentialGain;
      // Cap projected score: never show 100 if there are open remediation items — cap at 95
      const hasOpenRemediations = remedList.some(r => r.type === 'identity-remediation') || (critCount + highCount > 0);
      const maxProjected = hasOpenRemediations ? 95 : 100;
      return {
        current: postureScore, grade, tier, previous30d: prevPosture, delta30d,
        industryAvg: as?.industry_avg ?? Math.round(100 - (as?.score ?? 50)),
        target: as?.posture_target ?? (Number(settings?.settings?.posture_target) || Math.min(90, Math.round(postureScore + finalGain))),
        potentialGain: finalGain,
        projectedNoAction: Math.max(0, postureScore - (delta30d < 0 ? Math.abs(delta30d) : (critCount + highCount > 0 ? 3 : 1))),
        projectedRemediated: Math.min(maxProjected, postureScore + finalGain),
        history,
      };
    })(),
    pillars,
    topRiskDrivers: topDrivers.slice(0, 5),
    kpis: {
      privilegedNHIs: { count: ao.privileged_nhi_count || 0, description: `${nhi.nhi_pct ? nhi.nhi_pct.toFixed(0) : 0}% of high privilege from machines` },
      dormantPrivileged: { count: ao.dormant_privileged_count || 0, description: 'Unused >90 days with active roles' },
      subscriptionAccess: { count: ao.multi_sub_count || 0, description: 'Contributor+ at subscription scope' },
      rbacModifiers: { count: ao.rbac_modifier_count || 0, description: 'Can alter access policies directly' },
    },
    workloadExposure: {
      avgScore: we.component_averages?.total || 0,
      canEscalate: we.flags?.can_escalate || 0,
      orphaned: we.flags?.orphaned || 0,
      exposureDistribution: we.exposure_distribution || { critical: 0, high: 0, medium: 0, low: 0 },
      componentAverages: [
        { name: 'Privilege', score: we.component_averages?.privilege || 0, max: 40 },
        { name: 'Credential', score: we.component_averages?.credential_risk || 0, max: 25 },
        { name: 'Exposure', score: we.component_averages?.exposure || 0, max: 20 },
        { name: 'Lifecycle', score: we.component_averages?.lifecycle || 0, max: 20 },
        { name: 'Visibility', score: we.component_averages?.visibility || 0, max: 15 },
      ],
      lifecycleState: {
        active: lifecycleDist.active || 0, stale: lifecycleDist.possibly_active || lifecycleDist.stale || 0,
        dormant: (lifecycleDist.likely_dormant || 0) + (lifecycleDist.dormant || 0), blind: blindCount,
      },
      blindTooltip: `${blindCount} identities with no usage telemetry in last 30 days`,
      zombies: we.zombie_count || 0,
      crossSub: we.flags?.cross_subscription || 0,
      tenantScope: we.scope_distribution?.tenant || 0,
      topAffectedWorkloads: [],
    },
    remediations: remedList,
    systemActions,
    compliance: {
      frameworks: compFrameworks,
      controlMaturity: comp?.control_maturity || { preventive: 0, detective: 0, compensating: 0, missing: 0 },
      remediationProgress: Math.round(remed?.completion_pct || comp?.remediation_progress || 0),
      saGovernance: gov.ownership_coverage_pct || 0,
    },
    governance: {
      metrics: govMetrics,
      policyGaps,
      effectivenessScore: effScore,
      effectivenessTooltip: 'Based on ownership, PIM enforcement, review coverage, policy alignment',
      effectivenessConfigured,
      maturityLevel: getMaturityLevel(effScore, effectivenessConfigured),
    },
    trends: {
      movement30d: [
        { label: 'Critical Identities', previous: pr.critical_count || 0, current: critCount, direction: critCount > (pr.critical_count || 0) ? 'up' : critCount < (pr.critical_count || 0) ? 'down' : 'same' },
        { label: 'High-Risk Identities', previous: pr.high_count || 0, current: highCount, direction: highCount > (pr.high_count || 0) ? 'up' : highCount < (pr.high_count || 0) ? 'down' : 'same' },
        { label: 'Total Identities', previous: pr.total_identities || 0, current: totalIds, direction: totalIds > (pr.total_identities || 0) ? 'up' : 'same' },
        { label: 'New Identities', previous: 0, current: lr.new_identities || 0, direction: lr.new_identities ? 'up' : 'same' },
        { label: 'Removed', previous: 0, current: lr.removed_identities || 0, direction: lr.removed_identities ? 'down' : 'same' },
      ],
      noActionImpact: [
        ao.privileged_nhi_count ? `${ao.privileged_nhi_count} privileged NHIs remain without review` : null,
        ao.dormant_privileged_count ? `${ao.dormant_privileged_count} dormant privileged accounts retain active roles` : null,
        ao.rbac_modifier_count ? `${ao.rbac_modifier_count} RBAC modifiers continue unreviewed` : null,
        (gov.ownership_coverage_pct != null && gov.ownership_coverage_pct < 100)
          ? `Ownership gap at ${Math.round(100 - gov.ownership_coverage_pct)}% — ${(as?.pillars?.ownership_governance?.detail?.unowned_spns || 0)} SPNs unowned`
          : null,
        (as?.pillars?.usage_dormancy?.detail?.dormant || 0) > 0
          ? `${as.pillars.usage_dormancy.detail.dormant} dormant accounts with active roles unresolved`
          : null,
      ].filter((x): x is string => !!x),
      estimatedBreachImpact: postureScore <= 40 ? 'High' : postureScore <= 60 ? 'Moderate-High' : 'Moderate',
      remediatedBreachImpact: (() => {
        const hasOpen = remedList.some(r => r.type === 'identity-remediation') || (critCount + highCount > 0);
        const proj = Math.min(hasOpen ? 95 : 100, postureScore + potentialGain);
        return proj >= 80 ? 'Low' : proj >= 60 ? 'Moderate' : 'Moderate-High';
      })(),
      remediatedConsequences: (() => {
        // Derive from actual pillar data — state what NEEDS to happen, not false claims
        const items: string[] = [];
        const og = as?.pillars?.ownership_governance?.detail || {};
        const ug = as?.pillars?.usage_dormancy?.detail || {};
        const ep = as?.pillars?.effective_privilege?.detail || {};
        const cr = as?.pillars?.credential_risk?.detail || {};
        const ee = as?.pillars?.external_exposure?.detail || {};
        if (og.unowned_spns > 0) items.push(`Assign owners to ${og.unowned_spns} orphaned SPNs (${Math.round(gov.ownership_coverage_pct || 0)}% → 100%)`);
        if (ug.dormant > 0) items.push(`Review & disable ${ug.dormant} dormant accounts with active roles`);
        if (ep.t0t1 > 0) items.push(`Review ${ep.t0t1} T0/T1 privilege assignments for least-access`);
        if (cr.expired > 0) items.push(`Rotate ${cr.expired} expired credentials`);
        if (ee.tenant_scope > 0) items.push(`Scope down ${ee.tenant_scope} tenant-wide identities`);
        if (!items.length) items.push('No critical remediation actions identified');
        return items;
      })(),
      biggestContributor: {
        label: sortedPillars[0]?.name || 'Unknown',
        delta: `Score ${sortedPillars[0]?.score || 0}/100`,
        pillar: sortedPillars[0]?.name || '',
      },
    },
  };
}

// ═══════════════════════════════════════════════════════════════════════
// REUSABLE COMPONENTS
// ═══════════════════════════════════════════════════════════════════════

function ScoreRing({ score, grade, size = 110 }: { score: number; grade: string; size?: number }) {
  const strokeWidth = Math.max(4, Math.round(size * 0.07));
  const padding = Math.round(size * 0.05);
  const r = (size / 2) - strokeWidth - padding;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);
  const tier = getTier(score);
  const color = getTierColor(tier);
  const scoreFontSize = Math.min(32, Math.round(size * 0.24));
  const gradeFontSize = Math.min(13, Math.round(size * 0.12));
  const cx = size / 2;
  const cy = size / 2;
  // Position score + grade as a pair centered in the ring
  const scoreY = cy - Math.round(size * 0.08);
  const gradeY = cy + Math.round(size * 0.14);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}
      style={{ filter: `drop-shadow(0 0 8px ${color}55)` }}>
      <circle cx={cx} cy={cy} r={r} fill="none"
        stroke={P.bgActive} strokeWidth={strokeWidth} />
      <circle cx={cx} cy={cy} r={r} fill="none"
        stroke={color} strokeWidth={strokeWidth}
        strokeDasharray={circ} strokeDashoffset={offset}
        strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`}
        style={{ transition: 'stroke-dashoffset 1.5s ease' }} />
      <text x={cx} y={scoreY}
        textAnchor="middle" dominantBaseline="central"
        style={{ fontFamily: F.data, fontSize: scoreFontSize, fontWeight: 800, fill: P.textBright }}>
        {score.toFixed(1)}
      </text>
      <text x={cx} y={gradeY}
        textAnchor="middle" dominantBaseline="central"
        style={{ fontFamily: F.data, fontSize: gradeFontSize, fill: P.textMuted }}>
        {grade}
      </text>
    </svg>
  );
}

function RiskTierBadge({ tier }: { tier: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '4px 14px', borderRadius: 6,
      fontFamily: F.data, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1.5,
      color: getTierColor(tier), background: getTierBg(tier),
    }}>{tier}</span>
  );
}

function AutomationBadge({ level }: { level: string }) {
  const c = getAutomationConfig(level);
  return (
    <span style={{
      fontFamily: F.data, fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
      color: c.color, background: `${c.color}1f`, border: `1px solid ${c.color}33`,
    }}>{c.label}</span>
  );
}

function RollbackBadge({ safety }: { safety: string }) {
  const c = getRollbackConfig(safety);
  return (
    <span style={{
      fontFamily: F.data, fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
      color: c.color, background: `${c.color}1a`, border: `1px solid ${c.color}33`,
    }}>{c.icon} {c.label}</span>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  return <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: getSeverityColor(severity), marginRight: 8, flexShrink: 0 }} />;
}

function MiniProgressBar({ value, max = 100, color, height = 4 }: { value: number; max?: number; color: string; height?: number }) {
  return (
    <div style={{ width: '100%', height, borderRadius: height / 2, background: P.track }}>
      <div style={{ width: `${Math.min(100, (value / max) * 100)}%`, height: '100%', borderRadius: height / 2, background: color, transition: 'width 0.8s ease' }} />
    </div>
  );
}

function CircularGauge({ value, size = 36, strokeWidth = 3, color }: { value: number; size?: number; strokeWidth?: number; color: string }) {
  const r = (size - strokeWidth * 2) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (value / 100) * circ;
  return (
    <svg width={size} height={size}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={P.borderCard} strokeWidth={strokeWidth} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={strokeWidth}
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        style={{ transform: 'rotate(-90deg)', transformOrigin: '50% 50%', transition: 'stroke-dashoffset 1s ease' }} />
      <text x="50%" y="50%" textAnchor="middle" dominantBaseline="central"
        style={{ fontFamily: F.data, fontSize: 9, fontWeight: 700, fill: P.textBright }}>{value}%</text>
    </svg>
  );
}

function SparklineChart({ data, width = 200, height = 40, color }: { data: { day: number; score: number }[]; width?: number; height?: number; color: string }) {
  if (!data.length) return null;
  const minS = Math.min(...data.map(d => d.score)) - 2;
  const maxS = Math.max(...data.map(d => d.score)) + 2;
  const points = data.map((d, i) => {
    const x = (i / Math.max(1, data.length - 1)) * width;
    const y = height - ((d.score - minS) / (maxS - minS)) * height;
    return `${x},${y}`;
  }).join(' ');
  const last = data[data.length - 1];
  const lx = width;
  const ly = height - ((last.score - minS) / (maxS - minS)) * height;
  return (
    <svg width={width} height={height} style={{ overflow: 'visible' }}>
      <polyline points={points} fill="none" stroke={color} strokeWidth={1.5} />
      <circle cx={lx} cy={ly} r={3} fill={color} stroke={P.tooltipBg} strokeWidth={1.5} />
    </svg>
  );
}

function RadarChart({ pillars, size = 200, onLabelClick }: { pillars: PillarData[]; size?: number; onLabelClick?: (i: number) => void }) {
  const cx = size / 2, cy = size / 2, maxR = size / 2 - 30;
  const n = pillars.length;
  const angleStep = (2 * Math.PI) / n;
  const getPoint = (i: number, frac: number) => {
    const a = -Math.PI / 2 + i * angleStep;
    return { x: cx + Math.cos(a) * maxR * frac, y: cy + Math.sin(a) * maxR * frac };
  };
  const levels = [0.25, 0.5, 0.75, 1.0];
  const dataPoints = pillars.map((p, i) => getPoint(i, Math.min(1, p.score / 100)));
  const dataPoly = dataPoints.map(p => `${p.x},${p.y}`).join(' ');
  const shortNames = ['Priv', 'Cred', 'Trust', 'Usage', 'Owner', 'Expos'];
  return (
    <svg width={size} height={size}>
      {levels.map(l => (
        <polygon key={l} points={Array.from({ length: n }, (_, i) => { const p = getPoint(i, l); return `${p.x},${p.y}`; }).join(' ')}
          fill="none" stroke={P.borderCard} strokeWidth={1} />
      ))}
      {Array.from({ length: n }, (_, i) => {
        const p = getPoint(i, 1);
        return <line key={i} x1={cx} y1={cy} x2={p.x} y2={p.y} stroke={P.borderCard} />;
      })}
      <polygon points={dataPoly} fill="rgba(234,179,8,0.15)" stroke="#eab308" strokeWidth={1.5} />
      {dataPoints.map((p, i) => <circle key={i} cx={p.x} cy={p.y} r={3} fill="#eab308" />)}
      {pillars.map((_, i) => {
        const lp = getPoint(i, 1.22);
        return (
          <text key={i} x={lp.x} y={lp.y} textAnchor="middle" dominantBaseline="central"
            style={{ fontFamily: F.data, fontSize: 9, fill: P.textMuted, cursor: onLabelClick ? 'pointer' : 'default' }}
            onClick={() => onLabelClick?.(i)}>{shortNames[i] || ''}</text>
        );
      })}
    </svg>
  );
}

function Card({ children, style, glow }: { children: React.ReactNode; style?: React.CSSProperties; glow?: boolean }) {
  return (
    <div style={{
      background: P.bgCard, border: `1px solid ${P.borderCard}`,
      borderRadius: 12, padding: 20, backdropFilter: P.backdrop,
      ...(glow ? { boxShadow: P.glow } : {}),
      ...style,
    }}>{children}</div>
  );
}

function SectionTitle({ children, right }: { children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
      <span style={{ fontFamily: F.data, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 2, color: P.textMuted }}>{children}</span>
      {right}
    </div>
  );
}

function TooltipWrap({ content, children }: { content: string; children: React.ReactNode }) {
  const [show, setShow] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  return (
    <span ref={ref} style={{ position: 'relative', display: 'inline-block' }}
      onMouseEnter={() => setTimeout(() => setShow(true), 200)} onMouseLeave={() => setShow(false)}>
      {children}
      {show && (
        <span style={{
          position: 'absolute', bottom: '100%', left: '50%', transform: 'translateX(-50%)',
          background: P.tooltipBg, border: `1px solid ${P.tooltipBorder}`,
          padding: '8px 12px', borderRadius: 6, fontFamily: F.ui, fontSize: 11, color: P.textSub,
          maxWidth: 280, whiteSpace: 'normal', zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
          marginBottom: 8, pointerEvents: 'none',
        }}>{content}</span>
      )}
    </span>
  );
}

function TrendArrow({ value }: { value: number | null }) {
  const t = formatTrend(value);
  return <span style={{ fontFamily: F.data, fontSize: 10, fontWeight: 600, color: t.color }}>{t.text}</span>;
}

function DataFreshnessBar({ tenant, scoring }: { tenant: TenantData['tenant']; scoring: TenantData['scoringMethodology'] }) {
  const [showTip, setShowTip] = useState(false);
  return (
    <div style={{
      background: P.bgHover, borderBottom: `1px solid ${P.divider}`,
      padding: '6px 28px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      fontFamily: F.data, fontSize: 10, color: P.textDim, marginBottom: 16,
    }}>
      <div style={{ display: 'flex', gap: 4, alignItems: 'center', flexWrap: 'wrap' }}>
        <span>Scan coverage: <span style={{ color: P.textMuted, fontWeight: 600 }}>{tenant.scanCoverage}%</span> subs</span>
        <span style={{ color: P.textFaint }}>&middot;</span>
        <span>Data completeness: <span style={{ color: getCompletenessColor(tenant.dataCompleteness), fontWeight: 600 }}>{tenant.dataCompleteness}%</span></span>
        <span style={{ color: P.textFaint }}>&middot;</span>
        <span>Last updated: <span style={{ color: P.textMuted, fontWeight: 600 }}>{tenant.lastUpdatedAgo}</span></span>
        <span style={{ color: P.textFaint }}>&middot;</span>
        <span style={{ position: 'relative', display: 'inline-block' }}
          onMouseEnter={() => setShowTip(true)} onMouseLeave={() => setShowTip(false)}>
          <a href={scoring.url} target="_blank" rel="noopener noreferrer"
            style={{ color: P.accentIndigo, textDecoration: 'none', cursor: 'pointer' }}
            onMouseOver={e => (e.currentTarget.style.textDecoration = 'underline')}
            onMouseOut={e => (e.currentTarget.style.textDecoration = 'none')}>
            {scoring.label}
          </a>
          {showTip && (
            <span style={{
              position: 'absolute', bottom: '100%', left: '50%', transform: 'translateX(-50%)',
              background: P.tooltipBg, border: `1px solid ${P.tooltipBorder}`,
              padding: '8px 12px', borderRadius: 6, fontFamily: F.ui, fontSize: 11, color: P.textSub,
              maxWidth: 320, whiteSpace: 'normal', zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
              marginBottom: 8, pointerEvents: 'none',
            }}>{scoring.summary}</span>
          )}
        </span>
      </div>
      {tenant.isolationGuarantee && (
        <span style={{ color: P.textDim }}>{'\uD83D\uDD12'} {tenant.isolationGuarantee}</span>
      )}
    </div>
  );
}

function ProductionBadge() {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6, marginTop: 10, padding: '6px 12px',
      background: 'rgba(255,68,68,0.06)', border: '1px solid rgba(255,68,68,0.12)',
      borderRadius: 6, width: '100%',
    }}>
      <span style={{ fontSize: 12 }}>{'\u26A0'}</span>
      <span style={{ fontFamily: F.data, fontSize: 10, fontWeight: 600, color: '#ff4444' }}>Impacts production workloads</span>
    </div>
  );
}

function MaturityBadge({ level }: { level: string }) {
  const color = getMaturityColor(level);
  return (
    <span style={{
      display: 'inline-block', padding: '4px 14px', borderRadius: 6,
      fontFamily: F.data, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1,
      color, background: `${color}1f`, border: `1px solid ${color}40`,
    }}>{level}</span>
  );
}

function SystemActionChip({ action, onTrigger }: { action: SystemAction; onTrigger?: () => void }) {
  const statusConfig: Record<string, { color: string; icon: string; bg: string }> = {
    completed: { color: '#22c55e', icon: '\u2713', bg: 'rgba(34,197,94,0.1)' },
    'in-progress': { color: '#3b82f6', icon: '\u21BB', bg: 'rgba(59,130,246,0.1)' },
    pending: { color: '#eab308', icon: '\u25CB', bg: 'rgba(234,179,8,0.1)' },
    failed: { color: '#ff4444', icon: '\u2717', bg: 'rgba(255,68,68,0.1)' },
  };
  const cfg = statusConfig[action.status] || statusConfig.pending;
  return (
    <div style={{
      display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 12px',
      background: cfg.bg, border: `1px solid ${cfg.color}33`, borderRadius: 6,
      cursor: onTrigger ? 'pointer' : 'default',
    }} onClick={onTrigger}>
      <span style={{ fontFamily: F.data, fontSize: 12, color: cfg.color }}>{cfg.icon}</span>
      <div>
        <div style={{ fontFamily: F.ui, fontSize: 11, fontWeight: 600, color: P.textLight }}>{action.label}</div>
        <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim }}>{action.description}</div>
      </div>
      <span style={{
        fontFamily: F.data, fontSize: 9, fontWeight: 600, padding: '1px 6px', borderRadius: 3,
        color: cfg.color, background: `${cfg.color}1a`, textTransform: 'uppercase',
      }}>{action.status}</span>
    </div>
  );
}

function DrillableNumber({ value, label, onClick }: { value: number | string; label?: string; onClick?: () => void }) {
  const [hover, setHover] = useState(false);
  return (
    <span
      role="button" tabIndex={0} aria-label={label || `Drill into ${value}`}
      onClick={() => { onClick?.(); }}
      onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      style={{
        cursor: 'pointer', transition: 'all 0.15s ease',
        borderBottom: hover ? `1px solid ${P.accentIndigo}` : `1px dashed ${P.borderCard}`,
        color: hover ? P.accentIndigo : 'inherit',
        background: hover ? P.accentIndigoFaint : 'transparent',
        borderRadius: hover ? 2 : 0, paddingBottom: 1,
      }}
    >{value}</span>
  );
}

function NarrativeBanner({ narrative, exposure, tier, nav }: { narrative: string; exposure: TenantData['executiveSummary']['businessExposure']; tier: string; nav: Nav }) {
  const pct = getProductionExposurePct(exposure.productionWorkloads, exposure.totalProductionWorkloads);
  return (
    <div style={{
      background: 'rgba(255,140,0,0.04)', borderLeft: `3px solid ${getTierColor(tier)}`,
      padding: '16px 20px', borderRadius: '0 8px 8px 0', marginBottom: 20,
    }}>
      <div style={{ fontFamily: F.ui, fontSize: 14, color: P.textLight, fontStyle: 'italic', marginBottom: 8 }}>{narrative}</div>
      <div style={{ fontFamily: F.data, fontSize: 12, color: P.textMuted }}>
        <DrillableNumber value={exposure.identities} label="Drill into identities" onClick={() => nav('/identities')} /> identities <span style={{ color: P.textFaint }}>&bull;</span> <DrillableNumber value={exposure.subscriptions} label="View subscriptions" onClick={() => nav('/subscriptions')} /> subscriptions <span style={{ color: P.textFaint }}>&bull;</span> <DrillableNumber value={exposure.productionWorkloads} label="View workloads" onClick={() => nav('/workload-identities')} />{exposure.totalProductionWorkloads > 0 ? ` of ${exposure.totalProductionWorkloads}` : ''} production workloads <TooltipWrap content="Affected = identity has at least one role assignment, credential, or access policy that touches this workload's subscription/resource scope."><span style={{ borderBottom: `1px dashed ${P.borderCard}`, cursor: 'help' }}>affected</span></TooltipWrap>{pct > 0 ? ` (${pct}%)` : ''}
      </div>
    </div>
  );
}

function WorkloadTable({ workloads }: { workloads: AffectedWorkload[] }) {
  if (!workloads.length) return <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textDim, padding: 16 }}>No production workload data available</div>;
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>{['Name', 'Type', 'Region', 'Exposed IDs', 'Risk'].map(h => (
            <th key={h} style={{ fontFamily: F.data, fontSize: 9, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1.5, color: P.textDim, padding: '8px 12px', textAlign: 'left', borderBottom: `1px solid ${P.borderCard}` }}>{h}</th>
          ))}</tr>
        </thead>
        <tbody>
          {workloads.slice(0, 5).map((w, i) => (
            <tr key={i} style={{ background: i % 2 ? P.bgHover : 'transparent' }}>
              <td style={{ fontFamily: F.data, fontSize: 12, fontWeight: 600, color: P.textLight, padding: '8px 12px' }}>{w.name}</td>
              <td style={{ padding: '8px 12px' }}><span style={{ fontFamily: F.data, fontSize: 10, padding: '2px 8px', borderRadius: 4, background: P.accentIndigoSubtle, color: P.accentIndigo }}>{w.type}</span></td>
              <td style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted, padding: '8px 12px' }}>{w.region}</td>
              <td style={{ fontFamily: F.data, fontSize: 12, color: P.textLight, padding: '8px 12px' }}>{w.exposedIdentities}</td>
              <td style={{ padding: '8px 12px', display: 'flex', alignItems: 'center', gap: 6 }}><SeverityDot severity={w.riskLevel} /><span style={{ fontFamily: F.data, fontSize: 10, color: getSeverityColor(w.riskLevel), textTransform: 'capitalize' }}>{w.riskLevel}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// DRILL DOWN PANEL
// ═══════════════════════════════════════════════════════════════════════

interface DrillPanelState { open: boolean; title: string; filterUrl: string; identities: any[]; loading: boolean }

function DrillDownPanel({ state, onClose, onViewAll }: { state: DrillPanelState; onClose: () => void; onViewAll: () => void }) {
  if (!state.open) return null;
  return (
    <>
      {/* Backdrop */}
      <div onClick={onClose} style={{
        position: 'fixed', inset: 0, background: P.overlay, zIndex: 200,
        backdropFilter: 'blur(2px)', transition: 'opacity 0.2s ease',
      }} />
      {/* Panel */}
      <div style={{
        position: 'fixed', top: 0, right: 0, width: 420, height: '100vh', zIndex: 201,
        background: P.panelBg,
        borderLeft: `1px solid ${P.track}`, overflowY: 'auto',
        boxShadow: '-8px 0 24px rgba(0,0,0,0.3)', animation: 'drillSlideIn 0.25s ease',
      }}>
        <style>{`@keyframes drillSlideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }`}</style>
        <div style={{ padding: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <span style={{ fontFamily: F.data, fontSize: 12, fontWeight: 700, color: P.textLight, textTransform: 'uppercase', letterSpacing: 1 }}>{state.title}</span>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: P.textDim, cursor: 'pointer', fontSize: 18, padding: 4 }}>&times;</button>
          </div>

          {state.loading ? (
            <div style={{ textAlign: 'center', padding: 40 }}>
              <div style={{ width: 24, height: 24, border: `2px solid ${P.accentStrong}`, borderTopColor: 'transparent', borderRadius: '50%', margin: '0 auto', animation: 'spin 0.8s linear infinite' }} />
              <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
            </div>
          ) : !state.identities.length ? (
            <div style={{ fontFamily: F.ui, fontSize: 13, color: P.textDim, padding: 20, textAlign: 'center' }}>No identities match this filter</div>
          ) : (
            <div>
              {state.identities.slice(0, 15).map((id: any, i: number) => (
                <div key={id.id || i} style={{
                  display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px', marginBottom: 4,
                  background: i % 2 ? P.bgHover : 'transparent', borderRadius: 6,
                }}>
                  <SeverityDot severity={id.risk_level || 'low'} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textLight, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {id.display_name || id.identity_name || 'Unknown'}
                    </div>
                    <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim }}>{id.identity_category || ''}</div>
                  </div>
                  <span style={{ fontFamily: F.data, fontSize: 11, fontWeight: 700, color: getSeverityColor(id.risk_level || 'low') }}>
                    {id.risk_score != null ? id.risk_score : '\u2014'}
                  </span>
                </div>
              ))}
              {state.identities.length > 15 && (
                <div style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, padding: '8px 12px' }}>+ {state.identities.length - 15} more</div>
              )}
            </div>
          )}

          <button onClick={onViewAll} style={{
            width: '100%', marginTop: 16, padding: '10px 16px', borderRadius: 8, border: 'none', cursor: 'pointer',
            fontFamily: F.data, fontSize: 12, fontWeight: 700,
            background: P.btnGradient, color: 'white',
          }}>View All &rarr;</button>
        </div>
      </div>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// COMPLIANCE DETAIL PANEL
// ═══════════════════════════════════════════════════════════════════════

function ComplianceDetailPanel({ state, onClose, openDrill, setDrillPanel }: {
  state: { open: boolean; framework: Framework | null };
  onClose: () => void;
  openDrill: (title: string, filterUrl: string) => void;
  setDrillPanel: React.Dispatch<React.SetStateAction<DrillPanelState>>;
}) {
  if (!state.open || !state.framework) return null;
  const fw = state.framework;
  const sorted = [...fw.controls].sort((a, b) => {
    const so: Record<string, number> = { fail: 0, warn: 1, pass: 2 };
    const sev: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    if ((so[a.status] ?? 2) !== (so[b.status] ?? 2)) return (so[a.status] ?? 2) - (so[b.status] ?? 2);
    return (sev[a.severity] ?? 3) - (sev[b.severity] ?? 3);
  });
  const failCount = fw.controls.filter(c => c.status === 'fail').length;
  const warnCount = fw.controls.filter(c => c.status === 'warn').length;
  const passCount = fw.controls.filter(c => c.status === 'pass').length;
  const fwColor = fw.pct >= 60 ? '#22c55e' : fw.pct >= 30 ? '#eab308' : '#ff4444';

  const handleEvidence = (ctrl: ComplianceControl) => {
    if (ctrl.evidenceIdentities.length > 0) {
      setDrillPanel({ open: true, title: `${ctrl.controlId}: ${ctrl.name}`, filterUrl: ctrl.drilldownUrl || '/identities', identities: ctrl.evidenceIdentities, loading: false });
    } else if (ctrl.drilldownUrl) {
      openDrill(`${ctrl.controlId}: ${ctrl.name}`, ctrl.drilldownUrl);
    }
  };

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: P.overlayStrong, zIndex: 209, backdropFilter: 'blur(2px)' }} />
      <div style={{
        position: 'fixed', top: 0, right: 0, width: 560, height: '100vh', zIndex: 210,
        background: P.panelBg,
        borderLeft: `1px solid ${P.track}`, overflowY: 'auto',
        boxShadow: '-8px 0 32px rgba(0,0,0,0.4)', animation: 'compSlideIn 0.25s ease',
      }}>
        <style>{`@keyframes compSlideIn { from { transform: translateX(100%); } to { transform: translateX(0); } }`}</style>
        <div style={{ padding: 24 }}>
          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
              <CircularGauge value={fw.pct} size={48} color={fwColor} />
              <div>
                <div style={{ fontFamily: F.ui, fontSize: 16, fontWeight: 700, color: P.textBright }}>{fw.name}</div>
                <div style={{ fontFamily: F.data, fontSize: 11, color: P.textMuted }}><DrillableNumber value={`${fw.passed}/${fw.total}`} label={`${fw.name} controls`} onClick={() => openDrill(`${fw.name} Identities`, '/identities')} /> controls passing</div>
              </div>
            </div>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: P.textDim, cursor: 'pointer', fontSize: 22, padding: 4 }}>&times;</button>
          </div>

          {/* Pass/Warn/Fail badges */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
            <span style={{ fontFamily: F.data, fontSize: 10, padding: '3px 10px', borderRadius: 4, background: 'rgba(34,197,94,0.1)', color: '#22c55e' }}>{passCount} Pass</span>
            <span style={{ fontFamily: F.data, fontSize: 10, padding: '3px 10px', borderRadius: 4, background: 'rgba(234,179,8,0.1)', color: '#eab308' }}>{warnCount} Warn</span>
            <span style={{ fontFamily: F.data, fontSize: 10, padding: '3px 10px', borderRadius: 4, background: 'rgba(255,68,68,0.1)', color: '#ff4444' }}>{failCount} Fail</span>
          </div>

          {/* Controls list */}
          {sorted.length === 0 ? (
            <div style={{ fontFamily: F.ui, fontSize: 13, color: P.textDim, padding: 20, textAlign: 'center' }}>No controls data available. Run a discovery scan to populate compliance controls.</div>
          ) : sorted.map((ctrl, i) => {
            const statusColor = ctrl.status === 'pass' ? '#22c55e' : ctrl.status === 'warn' ? '#eab308' : '#ff4444';
            return (
              <div key={ctrl.controlId || i} style={{
                padding: '12px 14px', marginBottom: 6,
                background: i % 2 ? P.bgHover : 'transparent',
                borderRadius: 6, borderLeft: `3px solid ${statusColor}`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <SeverityDot severity={ctrl.severity} />
                  <span style={{ fontFamily: F.data, fontSize: 10, color: P.accentIndigo, background: P.accentIndigoSubtle, padding: '1px 6px', borderRadius: 3 }}>{ctrl.controlId}</span>
                  <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textLight, flex: 1, fontWeight: 600 }}>{ctrl.name}</span>
                  <span style={{ fontFamily: F.data, fontSize: 10, padding: '2px 8px', borderRadius: 4, color: statusColor, background: `${statusColor}1a`, textTransform: 'uppercase', fontWeight: 700 }}>{ctrl.status}</span>
                </div>
                <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted, marginBottom: 4, paddingLeft: 16 }}>{ctrl.detail}</div>
                <div style={{ display: 'flex', gap: 12, paddingLeft: 16, alignItems: 'center' }}>
                  <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}>Value: <span style={{ color: P.textSub }}>{ctrl.value}</span></span>
                  <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}>Threshold: <span style={{ color: P.textSub }}>{ctrl.passThreshold}</span></span>
                  {ctrl.status !== 'pass' && ctrl.evidenceCount > 0 && (
                    <span onClick={e => e.stopPropagation()}>
                      <DrillableNumber value={`${ctrl.evidenceCount} identities`} label={`Evidence for ${ctrl.controlId}`} onClick={() => handleEvidence(ctrl)} />
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// EXPORT MENU
// ═══════════════════════════════════════════════════════════════════════

function ExportMenu({ state, onClose }: { state: { open: boolean; framework: Framework | null; anchorRect: DOMRect | null }; onClose: () => void }) {
  if (!state.open || !state.framework || !state.anchorRect) return null;
  const fw = state.framework;

  const exportCSV = () => {
    const headers = ['Control ID', 'Name', 'Status', 'Severity', 'Value', 'Threshold', 'Detail'];
    const rows = fw.controls.map(c => [c.controlId, c.name, c.status, c.severity, String(c.value), c.passThreshold, c.detail]);
    const csvContent = [headers, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `${fw.key || fw.name.replace(/\s+/g, '_')}_controls.csv`;
    a.click(); URL.revokeObjectURL(url);
    onClose();
  };

  const exportPDF = () => {
    const doc = new jsPDF({ orientation: 'landscape' });
    doc.setFontSize(16); doc.text(fw.name, 14, 20);
    doc.setFontSize(10); doc.text(`${fw.passed}/${fw.total} controls passing (${fw.pct}%)`, 14, 28);
    autoTable(doc, {
      startY: 35,
      head: [['Control ID', 'Name', 'Status', 'Severity', 'Value', 'Threshold', 'Detail']],
      body: fw.controls.map(c => [c.controlId, c.name, c.status, c.severity, String(c.value), c.passThreshold, c.detail]),
      theme: 'grid', headStyles: { fillColor: [99, 102, 241] }, styles: { fontSize: 8 },
    });
    doc.save(`${fw.key || fw.name.replace(/\s+/g, '_')}_report.pdf`);
    onClose();
  };

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 299 }} />
      <div style={{
        position: 'fixed', top: state.anchorRect.top + state.anchorRect.height + 4,
        left: state.anchorRect.left, zIndex: 300,
        background: P.tooltipBg, border: `1px solid ${P.tooltipBorder}`,
        borderRadius: 8, padding: 4, boxShadow: '0 8px 24px rgba(0,0,0,0.5)', minWidth: 150,
      }}>
        {[
          { label: 'Export CSV', fn: exportCSV },
          { label: 'Export PDF', fn: exportPDF },
        ].map(opt => (
          <div key={opt.label} onClick={opt.fn} style={{
            padding: '8px 12px', cursor: 'pointer', borderRadius: 6,
            fontFamily: F.ui, fontSize: 12, color: P.textLight,
          }}
            onMouseEnter={e => (e.currentTarget.style.background = P.accentIndigoSubtle)}
            onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
          >{opt.label}</div>
        ))}
      </div>
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// COMPLIANCE FRAMEWORK CARD
// ═══════════════════════════════════════════════════════════════════════

function ComplianceFrameworkCard({ fw, onOpenDetail, onOpenExport, onDrillFailing }: {
  fw: Framework;
  onOpenDetail: () => void;
  onOpenExport: (rect: DOMRect) => void;
  onDrillFailing: () => void;
}) {
  const [hover, setHover] = useState(false);
  const fwColor = fw.pct >= 60 ? '#22c55e' : fw.pct >= 30 ? '#eab308' : '#ff4444';
  return (
    <div
      onClick={onOpenDetail}
      onMouseEnter={() => setHover(true)} onMouseLeave={() => setHover(false)}
      style={{
        display: 'flex', alignItems: 'center', gap: 12, padding: 12,
        background: P.bgHover, borderRadius: 8, cursor: 'pointer',
        border: `1px solid ${hover ? P.accentIndigoBg : 'transparent'}`,
        boxShadow: hover ? `0 0 12px ${P.accentIndigoSubtle}` : 'none',
        transition: 'all 0.2s ease',
      }}
    >
      <TooltipWrap content={fw.controlMappingSource}>
        <CircularGauge value={fw.pct} size={42} color={fwColor} />
      </TooltipWrap>
      <div style={{ flex: 1 }}>
        <div style={{ fontFamily: F.ui, fontSize: 13, color: P.textLight, fontWeight: 600 }}>{fw.name}</div>
        <div style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}><DrillableNumber value={`${fw.passed}/${fw.total}`} label={`${fw.name} controls`} onClick={onOpenDetail} /> controls</div>
        <div style={{ fontFamily: F.data, fontSize: 10, color: '#ff8c00' }}>
          <span onClick={e => { e.stopPropagation(); onDrillFailing(); }}>
            <DrillableNumber value={fw.failingIdentities} label={`Drill into ${fw.name} failures`} onClick={() => {}} />
          </span>
          {' '}identity control failures
        </div>
        <TrendArrow value={fw.coverageTrend30d} />
      </div>
      <div style={{ display: 'flex', gap: 6 }} onClick={e => e.stopPropagation()}>
        <button onClick={(e) => { e.stopPropagation(); onOpenExport(e.currentTarget.getBoundingClientRect()); }}
          style={{ fontFamily: F.data, fontSize: 9, padding: '3px 8px', borderRadius: 4, border: `1px solid ${P.accentIndigoSubtle}`, background: P.accentIndigoSubtle, color: P.accentIndigo, cursor: 'pointer' }}>Export</button>
        <button onClick={(e) => { e.stopPropagation(); onOpenDetail(); }}
          style={{ fontFamily: F.data, fontSize: 9, padding: '3px 8px', borderRadius: 4, border: `1px solid ${P.track}`, background: P.bgSubtle, color: P.textMuted, cursor: 'pointer' }}>Details</button>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 1: EXECUTIVE SUMMARY
// ═══════════════════════════════════════════════════════════════════════

function ExecutiveSummaryTab({ d, nav, openDrill, setActiveTab, openComplianceDetail }: { d: TenantData; nav: Nav; openDrill: (title: string, filterUrl: string) => void; setActiveTab: (tab: string) => void; openComplianceDetail: (fw: Framework) => void }) {
  const tier = d.riskScore.tier;
  const color = getTierColor(tier);
  const topFw: Framework[] = [];
  Object.values(d.compliance.frameworks).forEach(arr => arr.forEach(fw => topFw.push(fw)));
  const top6 = topFw.slice(0, 6);

  return (
    <div>
      {/* ROW 0: Narrative Banner */}
      <NarrativeBanner narrative={d.executiveSummary.riskNarrative} exposure={d.executiveSummary.businessExposure} tier={tier} nav={nav} />

      {/* ROW 1: Score + Top Risk Drivers */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <Card glow>
          <SectionTitle>Identity Attack Surface</SectionTitle>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            <ScoreRing score={d.riskScore.current} grade={d.riskScore.grade} />
            <div>
              <RiskTierBadge tier={tier} />
              <div style={{ marginTop: 12 }}>
                <div style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, marginBottom: 4 }}>vs 30 days</div>
                <span style={{ fontFamily: F.data, fontSize: 13, color: d.riskScore.delta30d >= 0 ? '#22c55e' : '#ff4444' }}>
                  {formatDelta(d.riskScore.delta30d)} pts
                </span>
              </div>
              <div style={{ display: 'flex', gap: 16, marginTop: 8, flexWrap: 'wrap' }}>
                {[
                  { l: 'Industry', v: d.riskScore.industryAvg, url: '/identities' },
                  { l: 'Target', v: d.riskScore.target, url: '/settings' },
                  { l: 'Potential', v: `+${d.riskScore.potentialGain}`, url: '/identities?risk_level=critical' },
                ].map(b => (
                  <div key={b.l}>
                    <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, textTransform: 'uppercase' }}>{b.l}</div>
                    <div style={{ fontFamily: F.data, fontSize: 13, color: P.textSub }}><DrillableNumber value={b.v} label={`${b.l} score`} onClick={() => nav(b.url)} /></div>
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 10 }}>
                <SparklineChart data={d.riskScore.history} width={160} height={30} color={color} />
              </div>
            </div>
          </div>
        </Card>

        <Card>
          <SectionTitle right={<span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}>{d.topRiskDrivers.length} drivers</span>}>Top Risk Drivers</SectionTitle>
          {d.topRiskDrivers.slice(0, 5).map((dr, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
              <SeverityDot severity={dr.impact} />
              <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textSub, flex: 1 }}>{dr.label}</span>
              <span style={{ fontFamily: F.data, fontSize: 9, color: P.textDim }}>{dr.pillar}</span>
            </div>
          ))}
        </Card>
      </div>

      {/* ROW 2: Immediate Actions + Compliance */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <Card>
          <SectionTitle>Immediate Actions</SectionTitle>
          {(() => {
            const identityRemediations = d.remediations.filter(r => r.type === 'identity-remediation' && r.gain > 0);
            if (!identityRemediations.length) return (
              <div style={{ padding: 16, background: P.bgHover, borderRadius: 8, textAlign: 'center' }}>
                <div style={{ fontFamily: F.ui, fontSize: 13, color: P.textMuted, marginBottom: 8 }}>No identity remediation actions available</div>
                <div style={{ fontFamily: F.data, fontSize: 11, color: P.textDim }}>Run a discovery scan to generate recommendations</div>
              </div>
            );
            return identityRemediations.slice(0, 3).map(r => (
              <div key={r.rank} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12, padding: 10, background: P.bgHover, borderRadius: 8 }}>
                <span style={{ fontFamily: F.data, fontSize: 18, fontWeight: 800, color: P.accentStrong, minWidth: 24 }}>#{r.rank}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontFamily: F.ui, fontSize: 13, color: P.textLight, fontWeight: 600 }}>{r.action}</div>
                  <div style={{ display: 'flex', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
                    <span style={{ fontFamily: F.data, fontSize: 16, color: '#22c55e', fontWeight: 700 }}>+{r.gain}</span>
                    <AutomationBadge level={r.automation} />
                    <RollbackBadge safety={r.rollbackSafety} />
                  </div>
                </div>
              </div>
            ));
          })()}
          <div style={{ marginTop: 8 }}>
            <div style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, marginBottom: 4 }}>Total potential gain: +{d.riskScore.potentialGain} pts</div>
            <MiniProgressBar value={d.riskScore.potentialGain} max={30} color={P.accentStrong} height={6} />
          </div>
        </Card>

        <Card>
          <SectionTitle right={<span style={{ fontFamily: F.data, fontSize: 9, color: P.accentIndigo, background: P.accentIndigoSubtle, padding: '2px 8px', borderRadius: 4 }}>Identity Controls Only</span>}>
            Compliance Gap Snapshot
          </SectionTitle>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 16 }}>
            {top6.map((fw, i) => {
              const fwColor = fw.pct >= 60 ? '#22c55e' : fw.pct >= 30 ? '#eab308' : '#ff4444';
              return (
                <div key={i} onClick={() => openComplianceDetail(fw)}
                  style={{ textAlign: 'center', cursor: 'pointer', padding: 8, borderRadius: 8, transition: 'background 0.15s' }}
                  onMouseEnter={e => (e.currentTarget.style.background = P.accentIndigoFaint)}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <CircularGauge value={fw.pct} color={fwColor} />
                  <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textSub, marginTop: 4 }}>{fw.name}</div>
                  <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim }}>{fw.passed}/{fw.total}</div>
                  <div style={{ fontFamily: F.data, fontSize: 9, color: '#ff8c00' }}>
                    <span onClick={e => e.stopPropagation()}>
                      <DrillableNumber value={fw.failingIdentities} label={`${fw.name} identity control failures`} onClick={() => {
                        const evIds = fw.controls.filter(c => c.status !== 'pass').flatMap(c => c.evidenceIdentities);
                        if (evIds.length > 0) openDrill(`${fw.name} Failures`, '/identities?risk_level=critical');
                        else setActiveTab('compliance');
                      }} />
                    </span>
                    {' '}identity control failures
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ display: 'flex', gap: 16 }}>
            <div style={{ flex: 1, cursor: 'pointer' }} onClick={() => setActiveTab('action')}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, marginBottom: 4 }}>Remediation</div>
              <MiniProgressBar value={d.compliance.remediationProgress} color={P.accentStrong} height={4} />
              <span style={{ fontFamily: F.data, fontSize: 10, color: P.textMuted }}><DrillableNumber value={`${d.compliance.remediationProgress}%`} label="Remediation progress" onClick={() => setActiveTab('action')} /></span>
            </div>
            <div style={{ flex: 1, cursor: 'pointer' }} onClick={() => setActiveTab('governance')}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, marginBottom: 4 }}>SA Governance</div>
              <MiniProgressBar value={d.compliance.saGovernance} color="#eab308" height={4} />
              <span style={{ fontFamily: F.data, fontSize: 10, color: P.textMuted }}><DrillableNumber value={`${d.compliance.saGovernance}%`} label="SA Governance" onClick={() => setActiveTab('governance')} /></span>
            </div>
          </div>
        </Card>
      </div>

      {/* ROW 3: Governance + 30-Day Projection */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Card>
          <SectionTitle>Governance Health</SectionTitle>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
            {d.governance.metrics.map((m, i) => (
              <div key={i} style={{ padding: 10, background: P.bgHover, borderRadius: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ fontSize: 14 }}>{m.icon}</span>
                  <span style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted }}>{m.label}</span>
                </div>
                {m.configured ? (
                  <>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 4 }}>
                      <span style={{ fontFamily: F.data, fontSize: 24, fontWeight: 800, color: P.textBright }}><DrillableNumber value={`${m.value}%`} label={`Drill into ${m.label}`} onClick={() => nav(GOV_NAV[m.label] || '/identities')} /></span>
                      <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}>/ <DrillableNumber value={`${m.target}%`} label={`${m.label} target`} onClick={() => nav('/settings')} /></span>
                    </div>
                    <MiniProgressBar value={m.value} max={m.target} color={m.value >= m.target ? '#22c55e' : m.value >= m.target * 0.5 ? '#eab308' : '#ff4444'} height={3} />
                    <div style={{ marginTop: 4 }}><TrendArrow value={m.trend30d} /></div>
                  </>
                ) : (
                  <div style={{ marginTop: 4 }}>
                    <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textDim, fontStyle: 'italic' }}>Not Configured</div>
                    <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, marginTop: 2 }}>Target: {m.target}%</div>
                    <span onClick={() => nav('/settings')} style={{ fontFamily: F.data, fontSize: 10, color: P.accentIndigo, cursor: 'pointer', marginTop: 4, display: 'inline-block' }}>Configure &rarr;</span>
                  </div>
                )}
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: P.bgHover, borderRadius: 8, cursor: 'pointer' }} onClick={() => nav('/service-accounts')}>
            {d.governance.effectivenessConfigured ? (
              <>
                <span style={{ fontFamily: F.data, fontSize: 36, fontWeight: 800, color: P.textBright }}><DrillableNumber value={d.governance.effectivenessScore} label="Governance effectiveness" onClick={() => nav('/service-accounts')} /></span>
                <div>
                  <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted }}>Governance Effectiveness</div>
                  <RiskTierBadge tier={getTier(d.governance.effectivenessScore)} />
                  <div style={{ marginTop: 4 }}><MaturityBadge level={d.governance.maturityLevel} /></div>
                </div>
                <TooltipWrap content={d.governance.effectivenessTooltip}>
                  <span style={{ cursor: 'help', fontFamily: F.data, fontSize: 12, color: P.textDim, marginLeft: 'auto' }}>{'\u2139'}</span>
                </TooltipWrap>
              </>
            ) : (
              <>
                <span style={{ fontFamily: F.data, fontSize: 36, fontWeight: 800, color: P.textFaint }}>&mdash;</span>
                <div>
                  <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted }}>Governance Effectiveness</div>
                  <span style={{ display: 'inline-block', padding: '4px 14px', borderRadius: 6, fontFamily: F.data, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1.5, color: P.textFaint, background: 'rgba(71,85,105,0.15)' }}>Not Configured</span>
                  <div style={{ marginTop: 4 }}><MaturityBadge level="Not Assessed" /></div>
                </div>
              </>
            )}
          </div>
          {!d.governance.effectivenessConfigured && (
            <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textDim, fontStyle: 'italic', marginTop: 8 }}>
              Governance controls not yet configured. Risk score reflects structural identity posture only.
            </div>
          )}
        </Card>

        <Card>
          <SectionTitle>30-Day Projection</SectionTitle>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ padding: 12, background: 'rgba(255,68,68,0.05)', borderRadius: 8, borderLeft: '3px solid #ff4444' }}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: '#ff4444', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>No Action</div>
              <div style={{ fontFamily: F.data, fontSize: 28, fontWeight: 800, color: P.textBright }}>{d.riskScore.projectedNoAction.toFixed(1)}</div>
              <RiskTierBadge tier={getTier(d.riskScore.projectedNoAction)} />
              <div style={{ marginTop: 12 }}>
                {d.trends.noActionImpact.map((c, i) => (
                  <div key={i} style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted, marginBottom: 4, paddingLeft: 12, position: 'relative' }}>
                    <span style={{ position: 'absolute', left: 0, color: '#ff4444' }}>&bull;</span>{c}
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 8, fontFamily: F.data, fontSize: 10, color: '#ff8c00' }}>
                Breach Impact: {d.trends.estimatedBreachImpact}
              </div>
            </div>
            <div style={{ padding: 12, background: 'rgba(34,197,94,0.05)', borderRadius: 8, borderLeft: '3px solid #22c55e' }}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: '#22c55e', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>Remediated</div>
              <div style={{ fontFamily: F.data, fontSize: 28, fontWeight: 800, color: P.textBright }}>{d.riskScore.projectedRemediated.toFixed(1)}</div>
              <RiskTierBadge tier={getTier(d.riskScore.projectedRemediated)} />
              <div style={{ marginTop: 12 }}>
                {d.trends.remediatedConsequences.map((c, i) => (
                  <div key={i} style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted, marginBottom: 4, paddingLeft: 12, position: 'relative' }}>
                    <span style={{ position: 'absolute', left: 0, color: '#22c55e' }}>&bull;</span>{c}
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 8, fontFamily: F.data, fontSize: 10, color: '#22c55e' }}>
                Breach Impact: {d.trends.remediatedBreachImpact}
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 2: IDENTITY RISK
// ═══════════════════════════════════════════════════════════════════════

function IdentityRiskTab({ d, nav }: { d: TenantData; nav: Nav }) {
  const [expandedPillar, setExpandedPillar] = useState<number | null>(null);
  const we = d.workloadExposure;
  const expDist = we.exposureDistribution;
  const totalExp = expDist.critical + expDist.high + expDist.medium + expDist.low;
  const lc = we.lifecycleState;
  const totalLc = lc.active + lc.stale + lc.dormant + lc.blind;

  return (
    <div>
      {/* ROW 1: Radar + Pillar Breakdown */}
      <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', gap: 16, marginBottom: 16 }}>
        <Card style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <RadarChart pillars={d.pillars} size={200} onLabelClick={(i) => setExpandedPillar(expandedPillar === i ? null : i)} />
        </Card>
        <Card>
          <SectionTitle right={<span style={{ fontFamily: F.data, fontSize: 9, color: P.textDim }}>Weighted Model</span>}>Pillar Breakdown</SectionTitle>
          <div style={{ fontFamily: F.ui, fontSize: 10, fontStyle: 'italic', color: P.textDim, marginBottom: 10, padding: '4px 10px', background: P.accentIndigoFaint, borderRadius: 4, display: 'inline-block' }}>
            Score scale: 0 = no risk &middot; 100 = maximum risk
          </div>
          {d.pillars.map((p, i) => {
            const pc = getPillarColor(p.score);
            const expanded = expandedPillar === i;
            return (
              <div key={i}>
                <div
                  style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '8px 0', cursor: 'pointer', background: expanded ? P.bgSubtle : 'transparent', borderRadius: 6, paddingLeft: 8, paddingRight: 8 }}
                  onClick={() => setExpandedPillar(expanded ? null : i)}
                >
                  <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, width: 12 }}>{expanded ? '\u25BE' : '\u25B8'}</span>
                  <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textLight, flex: 1 }}>{p.name}</span>
                  <span style={{ fontFamily: F.data, fontSize: 13, fontWeight: 700, color: pc, minWidth: 32, textAlign: 'right' }}><DrillableNumber value={p.score} label={`Drill into ${p.name}`} onClick={() => nav(PILLAR_NAV[p.name] || '/identities')} /></span>
                  <div style={{ width: 80 }}><MiniProgressBar value={p.score} color={pc} height={4} /></div>
                  <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, minWidth: 28 }}>{p.weight}%</span>
                  <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, minWidth: 80 }}>{p.detail}</span>
                </div>
                {expanded && (
                  <div style={{ paddingLeft: 32, paddingBottom: 8, transition: 'max-height 0.3s ease' }}>
                    {p.drilldown.map((dd, j) => (
                      <div key={j} style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6 }}>
                        <SeverityDot severity={dd.impact} />
                        <span style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted }}>{dd.label}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </Card>
      </div>

      {/* ROW 2: KPI Cards (4 columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 16 }}>
        {[
          { title: 'Privileged NHIs', ...d.kpis.privilegedNHIs },
          { title: 'Dormant Privileged', ...d.kpis.dormantPrivileged },
          { title: 'Subscription Access', ...d.kpis.subscriptionAccess },
          { title: 'RBAC Modifiers', ...d.kpis.rbacModifiers },
        ].map((k, i) => (
          <Card key={i}>
            <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, textTransform: 'uppercase', letterSpacing: 1.5, marginBottom: 8 }}>{k.title}</div>
            <div style={{ fontFamily: F.data, fontSize: 36, fontWeight: 800, color: P.textBright }}><DrillableNumber value={k.count} label={`Drill into ${k.title}`} onClick={() => nav(KPI_NAV[k.title] || '/identities')} /></div>
            <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted, marginTop: 4 }}>{k.description}</div>
          </Card>
        ))}
      </div>

      {/* ROW 3: Identity-to-Workload Blast Radius */}
      <Card style={{ marginBottom: 16 }}>
        <SectionTitle right={<span style={{ fontFamily: F.data, fontSize: 10, color: P.accentIndigo, cursor: 'pointer' }}>Deep Dive &rarr;</span>}>
          Identity-to-Workload Blast Radius
        </SectionTitle>

        {/* Exposure Distribution Bar */}
        <div style={{ display: 'flex', height: 20, borderRadius: 4, overflow: 'hidden', marginBottom: 12 }}>
          {totalExp > 0 && [
            { key: 'critical', count: expDist.critical, color: '#ff4444' },
            { key: 'high', count: expDist.high, color: '#ff8c00' },
            { key: 'medium', count: expDist.medium, color: '#eab308' },
            { key: 'low', count: expDist.low, color: '#22c55e' },
          ].map(s => s.count > 0 ? (
            <div key={s.key} title={`${s.key}: ${s.count}`} onClick={() => nav(`/workload-identities?risk_level=${s.key}`)}
              style={{ width: `${(s.count / totalExp) * 100}%`, background: s.color, transition: 'width 0.5s ease', cursor: 'pointer' }} />
          ) : null)}
        </div>
        <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
          {[{ l: 'Avg Score', v: we.avgScore.toFixed(1) }, { l: 'Can Escalate', v: we.canEscalate }, { l: 'Orphaned', v: we.orphaned }].map(s => (
            <div key={s.l}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, textTransform: 'uppercase' }}>{s.l}</div>
              <div style={{ fontFamily: F.data, fontSize: 18, fontWeight: 700, color: P.textLight }}><DrillableNumber value={s.v} label={`Drill into ${s.l}`} onClick={() => nav(WORKLOAD_NAV[s.l] || '/workload-identities')} /></div>
            </div>
          ))}
        </div>

        {/* Component Averages */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, marginBottom: 16 }}>
          {we.componentAverages.map((c, i) => {
            const pct = (c.score / c.max) * 100;
            const cc = pct >= 80 ? '#ff4444' : pct >= 50 ? '#ff8c00' : pct >= 20 ? '#eab308' : '#22c55e';
            return (
              <div key={i} style={{ textAlign: 'center' }}>
                <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, marginBottom: 4 }}>{c.name}</div>
                <div style={{ fontFamily: F.data, fontSize: 14, fontWeight: 700, color: cc }}><DrillableNumber value={c.score.toFixed(1)} label={`Drill into ${c.name}`} onClick={() => nav('/workload-identities')} /></div>
                <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint }}>/{c.max}</div>
                <MiniProgressBar value={c.score} max={c.max} color={cc} height={3} />
              </div>
            );
          })}
        </div>

        {/* Lifecycle State Bar */}
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, marginBottom: 4, textTransform: 'uppercase' }}>Lifecycle State</div>
          <div style={{ display: 'flex', height: 16, borderRadius: 4, overflow: 'hidden' }}>
            {totalLc > 0 && [
              { key: 'Active', count: lc.active, color: '#22c55e' },
              { key: 'Stale', count: lc.stale, color: '#eab308' },
              { key: 'Dormant', count: lc.dormant, color: '#ff8c00' },
              { key: 'Blind', count: lc.blind, color: P.textDim },
            ].map(s => s.count > 0 ? (
              <TooltipWrap key={s.key} content={s.key === 'Blind' ? we.blindTooltip : `${s.key}: ${s.count}`}>
                <div onClick={() => nav(LIFECYCLE_NAV[s.key] || '/identities')} style={{ width: `${(s.count / totalLc) * 100}%`, background: s.color, height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer' }}>
                  <span style={{ fontFamily: F.data, fontSize: 8, color: '#fff', textShadow: '0 1px 2px rgba(0,0,0,0.5)' }}>{s.key} {s.count}</span>
                </div>
              </TooltipWrap>
            ) : null)}
          </div>
        </div>

        {/* Zombies / Cross Sub / Tenant Scope */}
        <div style={{ display: 'flex', gap: 16 }}>
          {[{ l: 'Zombies', v: we.zombies }, { l: 'Cross-Sub', v: we.crossSub }, { l: 'Tenant Scope', v: we.tenantScope }].map(s => (
            <div key={s.l} style={{ padding: '8px 14px', background: P.bgHover, borderRadius: 6 }}>
              <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, textTransform: 'uppercase' }}>{s.l}</div>
              <div style={{ fontFamily: F.data, fontSize: 18, fontWeight: 700, color: P.textLight }}><DrillableNumber value={s.v} label={`Drill into ${s.l}`} onClick={() => nav(WORKLOAD_NAV[s.l] || '/identities')} /></div>
            </div>
          ))}
        </div>
      </Card>

      {/* ROW 4: Top Affected Production Workloads */}
      {we.topAffectedWorkloads.length > 0 && (
        <Card>
          <SectionTitle>Top Affected Production Workloads</SectionTitle>
          <WorkloadTable workloads={we.topAffectedWorkloads} />
        </Card>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 3: ACTION PLAN
// ═══════════════════════════════════════════════════════════════════════

function ActionPlanTab({ d, nav }: { d: TenantData; nav: Nav }) {
  const identityRemediations = d.remediations.filter(r => r.type === 'identity-remediation' && r.gain > 0);
  const [scanTriggered, setScanTriggered] = useState(false);

  const triggerScan = useCallback(() => {
    if (scanTriggered) return;
    setScanTriggered(true);
    fetch('/api/runs/trigger', { method: 'POST' })
      .then(r => { if (!r.ok) throw new Error('Failed'); })
      .catch(() => setScanTriggered(false));
  }, [scanTriggered]);

  return (
    <div>
      {/* System Actions Bar */}
      {d.systemActions.length > 0 && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
          {d.systemActions.map(sa => (
            <SystemActionChip key={sa.id} action={sa}
              onTrigger={sa.id === 'run-scan' && !scanTriggered ? triggerScan : undefined} />
          ))}
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <SectionTitle>Highest Impact Remediations</SectionTitle>
        <span style={{ fontFamily: F.data, fontSize: 13, color: '#22c55e', fontWeight: 700 }}>Potential Gain: +{d.riskScore.potentialGain} pts</span>
      </div>

      {/* Empty state when no identity remediations */}
      {!identityRemediations.length && (
        <Card style={{ textAlign: 'center', padding: 40 }}>
          <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.3 }}>{'\uD83D\uDD0D'}</div>
          <div style={{ fontFamily: F.ui, fontSize: 15, color: P.textMuted, marginBottom: 8 }}>No identity remediation actions available</div>
          <div style={{ fontFamily: F.data, fontSize: 12, color: P.textDim, maxWidth: 400, margin: '0 auto', marginBottom: 16 }}>
            Run a discovery scan to analyze your identity estate and generate prioritized remediation recommendations.
          </div>
          <button
            onClick={triggerScan}
            disabled={scanTriggered}
            style={{
              fontFamily: F.data, fontSize: 12, fontWeight: 700, padding: '8px 24px', borderRadius: 8, border: 'none', cursor: scanTriggered ? 'default' : 'pointer',
              background: scanTriggered ? P.accentIndigoBg : P.btnGradient, color: 'white', opacity: scanTriggered ? 0.6 : 1,
            }}
          >{scanTriggered ? 'Scan Triggered...' : 'Run Discovery Scan'}</button>
        </Card>
      )}

      {identityRemediations.map((r, idx) => (
        <Card key={r.rank} style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontFamily: F.data, fontSize: 22, fontWeight: 800, color: P.accentStrong }}>#{idx + 1}</span>
              <div>
                <div style={{ fontFamily: F.ui, fontSize: 14, color: P.textBright, fontWeight: 600 }}>{r.action}</div>
                <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted, marginTop: 2 }}>{r.description}</div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontFamily: F.data, fontSize: 22, fontWeight: 800, color: '#22c55e' }}>+{r.gain}</span>
              <span style={{
                fontFamily: F.data, fontSize: 10, fontWeight: 700, padding: '4px 10px', borderRadius: 4,
                background: r.complexity === 'LOW' ? 'rgba(34,197,94,0.1)' : r.complexity === 'MEDIUM' ? 'rgba(234,179,8,0.1)' : 'rgba(255,68,68,0.1)',
                color: r.complexity === 'LOW' ? '#22c55e' : r.complexity === 'MEDIUM' ? '#eab308' : '#ff4444',
              }}>{r.complexity}</span>
              <button style={{
                fontFamily: F.data, fontSize: 12, fontWeight: 700, padding: '6px 16px', borderRadius: 8, border: 'none', cursor: 'pointer',
                background: P.btnGradient, color: 'white',
              }}>Start Fix &rarr;</button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12 }}>
            {[
              { l: 'Confidence', v: `${r.confidence}%`, drillUrl: null as string | null },
              { l: 'Est. Days', v: `~${r.estimatedDays}`, drillUrl: null as string | null },
              { l: 'Automation', v: null as string | null, comp: <AutomationBadge level={r.automation} />, drillUrl: null as string | null },
              { l: 'Blast Radius', v: null as string | null, drillUrl: '/identities', comp: <span><DrillableNumber value={r.blastRadius.identities} label="Affected identities" onClick={() => nav('/identities')} /> ids &middot; <DrillableNumber value={r.blastRadius.subscriptions} label="Affected subscriptions" onClick={() => nav('/subscriptions')} /> subs &middot; <DrillableNumber value={r.blastRadius.workloads} label="Affected workloads" onClick={() => nav('/workload-identities')} /> wklds</span> },
              { l: 'Rollback', v: null as string | null, comp: <RollbackBadge safety={r.rollbackSafety} />, drillUrl: null as string | null },
              { l: 'Pts/Day', v: `${getRiskPerDay(r.gain, r.estimatedDays)} pts/day`, drillUrl: null as string | null },
            ].map((chip, i) => (
              <div key={i} style={{ padding: '6px 8px', background: P.bgHover, borderRadius: 6 }}>
                <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, textTransform: 'uppercase', marginBottom: 2 }}>{chip.l}</div>
                {chip.comp || <div style={{ fontFamily: F.data, fontSize: 11, color: P.textSub }}>{chip.v}</div>}
              </div>
            ))}
          </div>
          {r.impactsProduction && <ProductionBadge />}
        </Card>
      ))}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 4: CONTROL & GOVERNANCE
// ═══════════════════════════════════════════════════════════════════════

function ControlGovernanceTab({ d, nav }: { d: TenantData; nav: Nav }) {
  const gov = d.governance;
  return (
    <div>
      {/* Governance Metrics (4-column) */}
      <Card style={{ marginBottom: 16 }}>
        <SectionTitle>Governance Metrics</SectionTitle>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
          {gov.metrics.map((m, i) => (
            <div key={i} style={{ padding: 14, background: P.bgHover, borderRadius: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <span style={{ fontSize: 16 }}>{m.icon}</span>
                <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted }}>{m.label}</span>
              </div>
              {m.configured ? (
                <>
                  <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                    <span style={{ fontFamily: F.data, fontSize: 28, fontWeight: 800, color: P.textBright }}><DrillableNumber value={`${m.value}%`} label={`Drill into ${m.label}`} onClick={() => nav(GOV_NAV[m.label] || '/identities')} /></span>
                    <span style={{ fontFamily: F.data, fontSize: 11, color: P.textDim }}>/ <DrillableNumber value={`${m.target}%`} label={`${m.label} target`} onClick={() => nav('/settings')} /></span>
                  </div>
                  <MiniProgressBar value={m.value} max={m.target} color={m.value >= m.target ? '#22c55e' : m.value >= m.target * 0.5 ? '#eab308' : '#ff4444'} height={4} />
                  <div style={{ marginTop: 6 }}><TrendArrow value={m.trend30d} /></div>
                </>
              ) : (
                <>
                  <div style={{ fontFamily: F.data, fontSize: 22, fontWeight: 800, color: P.textFaint, marginBottom: 4 }}>&mdash;</div>
                  <div style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, textTransform: 'uppercase', letterSpacing: 0.5 }}>Not Configured</div>
                  <div style={{ marginTop: 6 }}>
                    <span onClick={() => nav('/settings')} style={{ fontFamily: F.data, fontSize: 10, color: P.accentStrong, cursor: 'pointer' }}>Configure &rarr;</span>
                  </div>
                </>
              )}
            </div>
          ))}
        </div>
      </Card>

      {/* Control Failures + Effectiveness */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Card>
          <SectionTitle>Control Failures</SectionTitle>
          {gov.policyGaps.preventiveFailures.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontFamily: F.data, fontSize: 10, color: '#ff4444', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>{'\u25B8'} Preventive Failures</div>
              {gov.policyGaps.preventiveFailures.map((g, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <SeverityDot severity={g.severity} />
                  <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textSub, flex: 1 }}>{g.label}</span>
                  <span style={{ fontFamily: F.data, fontSize: 11, color: P.textMuted }}><DrillableNumber value={g.count} label={`Drill into ${g.label}`} onClick={() => nav(POLICY_GAP_NAV[g.label] || '/identities')} /></span>
                </div>
              ))}
            </div>
          )}
          {gov.policyGaps.operationalGaps.length > 0 && (
            <div>
              <div style={{ fontFamily: F.data, fontSize: 10, color: '#ff8c00', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>{'\u25B8'} Operational Gaps</div>
              {gov.policyGaps.operationalGaps.map((g, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                  <SeverityDot severity={g.severity} />
                  <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textSub, flex: 1 }}>{g.label}</span>
                  <span style={{ fontFamily: F.data, fontSize: 11, color: P.textMuted }}><DrillableNumber value={g.count} label={`Drill into ${g.label}`} onClick={() => nav(POLICY_GAP_NAV[g.label] || '/identities')} /></span>
                </div>
              ))}
            </div>
          )}
          {gov.policyGaps.preventiveFailures.length === 0 && gov.policyGaps.operationalGaps.length === 0 && (
            <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textDim }}>No policy gaps detected</div>
          )}
        </Card>

        <Card>
          <SectionTitle>Governance Effectiveness</SectionTitle>
          {gov.effectivenessConfigured ? (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 16 }}>
                <span style={{ fontFamily: F.data, fontSize: 48, fontWeight: 800, color: P.textBright }}><DrillableNumber value={gov.effectivenessScore} label="Governance effectiveness" onClick={() => nav('/service-accounts')} /></span>
                <div>
                  <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted, marginBottom: 4 }}>/ 100</div>
                  <RiskTierBadge tier={getTier(gov.effectivenessScore)} />
                  <div style={{ marginTop: 6 }}><MaturityBadge level={d.governance.maturityLevel} /></div>
                </div>
                <TooltipWrap content={gov.effectivenessTooltip}>
                  <span style={{ cursor: 'help', fontFamily: F.data, fontSize: 14, color: P.textDim, marginLeft: 'auto' }}>{'\u2139'}</span>
                </TooltipWrap>
              </div>
              <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted }}>
                Governance effectiveness measures the combined strength of ownership coverage, PIM enforcement, access review completion, and policy alignment across your identity estate.
              </div>
            </>
          ) : (
            <>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 16 }}>
                <span style={{ fontFamily: F.data, fontSize: 48, fontWeight: 800, color: P.textFaint }}>&mdash;</span>
                <div>
                  <div style={{ fontFamily: F.data, fontSize: 10, fontWeight: 700, padding: '3px 8px', borderRadius: 4, background: 'rgba(71,85,105,0.15)', color: P.textDim, textTransform: 'uppercase', letterSpacing: 0.5, display: 'inline-block', marginBottom: 4 }}>NOT CONFIGURED</div>
                  <div><MaturityBadge level="Not Assessed" /></div>
                </div>
              </div>
              <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textDim }}>
                Configure ownership, PIM, and access review policies in <span onClick={() => nav('/settings')} style={{ color: P.accentStrong, cursor: 'pointer' }}>Settings</span> to enable governance effectiveness scoring.
              </div>
            </>
          )}
        </Card>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 5: COMPLIANCE & EVIDENCE
// ═══════════════════════════════════════════════════════════════════════

function ComplianceEvidenceTab({ d, nav, openDrill, setActiveTab, openComplianceDetail, openExportMenu }: {
  d: TenantData; nav: Nav;
  openDrill: (title: string, filterUrl: string) => void;
  setActiveTab: (tab: string) => void;
  openComplianceDetail: (fw: Framework) => void;
  openExportMenu: (fw: Framework, rect: DOMRect) => void;
}) {
  const catIcons: Record<string, string> = { Privacy: '\uD83D\uDD12', Benchmark: '\uD83D\uDCCA', Industry: '\uD83C\uDFE5', 'Core Governance': '\uD83D\uDEE1' };
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const toggleCat = (cat: string) => setCollapsed(prev => ({ ...prev, [cat]: !prev[cat] }));
  const [highlightedMaturity, setHighlightedMaturity] = useState<string | null>(null);

  return (
    <div>
      <Card style={{ marginBottom: 16 }}>
        <SectionTitle right={<span style={{ fontFamily: F.data, fontSize: 9, color: P.accentIndigo, background: P.accentIndigoSubtle, padding: '2px 8px', borderRadius: 4 }}>Identity Controls Only</span>}>
          Compliance Posture
        </SectionTitle>
        {Object.entries(d.compliance.frameworks).map(([cat, fws]) => (
          <div key={cat} style={{ marginBottom: 20 }}>
            <div onClick={() => toggleCat(cat)}
              style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted, marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none' }}>
              <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, transition: 'transform 0.2s', display: 'inline-block',
                transform: collapsed[cat] ? 'rotate(0deg)' : 'rotate(90deg)' }}>&#9654;</span>
              <span>{catIcons[cat] || '\uD83D\uDCCB'}</span> {cat}
              <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint }}>({fws.length})</span>
            </div>
            {!collapsed[cat] && (
              <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.min(fws.length, 4)}, 1fr)`, gap: 12 }}>
                {fws.map((fw, i) => (
                  <ComplianceFrameworkCard key={i} fw={fw}
                    onOpenDetail={() => openComplianceDetail(fw)}
                    onOpenExport={(rect) => openExportMenu(fw, rect)}
                    onDrillFailing={() => {
                      const evIds = fw.controls.filter(c => c.status !== 'pass').flatMap(c => c.evidenceIdentities);
                      if (evIds.length > 0) openDrill(`${fw.name} — Failing Identities`, '/identities?risk_level=critical');
                      else openDrill(`${fw.name} — Failing Identities`, '/identities');
                    }}
                  />
                ))}
              </div>
            )}
          </div>
        ))}
      </Card>

      {/* Control Maturity + Progress */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Card>
          <SectionTitle>Control Maturity</SectionTitle>
          {[
            { l: 'Preventive', v: d.compliance.controlMaturity.preventive, color: '#22c55e' },
            { l: 'Detective', v: d.compliance.controlMaturity.detective, color: '#3b82f6' },
            { l: 'Compensating', v: d.compliance.controlMaturity.compensating, color: '#eab308' },
            { l: 'Missing', v: d.compliance.controlMaturity.missing, color: '#ff4444' },
          ].map((m, i) => (
            <div key={i}
              onClick={() => setHighlightedMaturity(highlightedMaturity === m.l ? null : m.l)}
              style={{
                display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10, cursor: 'pointer',
                padding: '4px 8px', borderRadius: 6, transition: 'background 0.15s',
                background: highlightedMaturity === m.l ? P.accentIndigoFaint : 'transparent',
              }}
              onMouseEnter={e => { if (highlightedMaturity !== m.l) e.currentTarget.style.background = P.bgActive; }}
              onMouseLeave={e => { if (highlightedMaturity !== m.l) e.currentTarget.style.background = 'transparent'; }}
            >
              <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: m.color }} />
              <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textSub, flex: 1 }}>{m.l}</span>
              <span style={{ fontFamily: F.data, fontSize: 14, fontWeight: 700, color: P.textBright }}>{m.v}</span>
            </div>
          ))}
        </Card>
        <Card>
          <SectionTitle>Progress &amp; Governance</SectionTitle>
          <div style={{ marginBottom: 16, cursor: 'pointer' }} onClick={() => setActiveTab('action')}>
            <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted, marginBottom: 4 }}>Remediation Progress</div>
            <MiniProgressBar value={d.compliance.remediationProgress} color={P.accentStrong} height={8} />
            <span style={{ fontFamily: F.data, fontSize: 12, color: P.textLight }}><DrillableNumber value={`${d.compliance.remediationProgress}%`} label="Remediation progress" onClick={() => setActiveTab('action')} /></span>
          </div>
          <div style={{ cursor: 'pointer' }} onClick={() => setActiveTab('governance')}>
            <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted, marginBottom: 4 }}>SA Governance</div>
            <MiniProgressBar value={d.compliance.saGovernance} color="#eab308" height={8} />
            <span style={{ fontFamily: F.data, fontSize: 12, color: P.textLight }}><DrillableNumber value={`${d.compliance.saGovernance}%`} label="SA Governance" onClick={() => setActiveTab('governance')} /></span>
          </div>
        </Card>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// TAB 6: RISK MOVEMENT
// ═══════════════════════════════════════════════════════════════════════

function RiskMovementTab({ d, nav }: { d: TenantData; nav: Nav }) {
  const tier = d.riskScore.tier;
  const color = getTierColor(tier);
  return (
    <div>
      {/* Full-width sparkline */}
      <Card style={{ marginBottom: 16 }}>
        <SectionTitle>Score Trajectory &mdash; 30 Days</SectionTitle>
        <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
          <SparklineChart data={d.riskScore.history} width={500} height={60} color={color} />
          <div style={{ textAlign: 'center' }}>
            <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, textTransform: 'uppercase' }}>Projected</div>
            <div style={{ fontFamily: F.data, fontSize: 24, fontWeight: 800, color: P.textBright }}>{d.riskScore.projectedNoAction.toFixed(1)}</div>
            <RiskTierBadge tier={getTier(d.riskScore.projectedNoAction)} />
          </div>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
          <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint }}>Day 1</span>
          <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint }}>Day 15</span>
          <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint }}>Day 30</span>
        </div>
      </Card>

      {/* Movement table + No Action */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <Card>
          <SectionTitle>Risk Movement &mdash; 30 Days</SectionTitle>
          {d.trends.movement30d.map((t, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10, padding: '6px 0', borderBottom: `1px solid ${P.divider}` }}>
              <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textSub, flex: 1 }}>{t.label}</span>
              <span style={{ fontFamily: F.data, fontSize: 12, color: P.textDim }}><DrillableNumber value={t.previous} label={`Previous ${t.label}`} onClick={() => nav(MOVE_NAV[t.label] || '/identities')} /></span>
              <span style={{ fontFamily: F.data, fontSize: 10, color: P.textFaint }}>&rarr;</span>
              <span style={{ fontFamily: F.data, fontSize: 12, color: P.textLight, fontWeight: 600 }}><DrillableNumber value={t.current} label={`Drill into ${t.label}`} onClick={() => nav(MOVE_NAV[t.label] || '/identities')} /></span>
              <span style={{
                fontFamily: F.data, fontSize: 10, fontWeight: 600,
                color: t.direction === 'up' ? '#ff4444' : t.direction === 'down' ? '#22c55e' : '#64748b',
              }}>{t.direction === 'up' ? '\u2191' : t.direction === 'down' ? '\u2193' : '\u2014'}</span>
            </div>
          ))}
        </Card>

        <Card>
          {/* What Changed Most box */}
          <div style={{ padding: 12, background: 'rgba(255,140,0,0.06)', borderRadius: 8, marginBottom: 16, borderLeft: '3px solid #ff8c00' }}>
            <div style={{ fontFamily: F.data, fontSize: 9, color: '#ff8c00', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>What Changed Most</div>
            <div style={{ fontFamily: F.ui, fontSize: 13, color: P.textLight, fontWeight: 600 }}>{d.trends.biggestContributor.label}</div>
            <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
              <span style={{ fontFamily: F.data, fontSize: 11, color: '#ff8c00' }}>{d.trends.biggestContributor.delta}</span>
              <span style={{ fontFamily: F.data, fontSize: 9, padding: '1px 6px', borderRadius: 3, background: P.bgActive, color: P.textMuted }}>{d.trends.biggestContributor.pillar}</span>
            </div>
          </div>

          <SectionTitle>If No Action Taken</SectionTitle>
          {d.trends.noActionImpact.map((c, i) => (
            <div key={i} style={{ fontFamily: F.ui, fontSize: 11, color: P.textMuted, marginBottom: 6, paddingLeft: 12, position: 'relative' }}>
              <span style={{ position: 'absolute', left: 0, color: '#ff4444' }}>&bull;</span>{c}
            </div>
          ))}
          <div style={{ marginTop: 10, fontFamily: F.data, fontSize: 10, color: '#ff8c00' }}>
            Estimated Breach Impact: {d.trends.estimatedBreachImpact}
          </div>
        </Card>
      </div>

      {/* Model Confidence Footer */}
      <Card style={{ background: P.bgCardMuted }}>
        <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', alignItems: 'center' }}>
          {[
            { l: 'Confidence', v: d.tenant.scanConfidence },
            { l: 'Last Scan', v: new Date(d.tenant.lastScan).toLocaleString() },
            { l: 'Sources', v: d.tenant.sources.join(', ') },
            { l: 'Duration', v: `${d.tenant.scanDuration.toFixed(1)}s` },
            { l: 'Completeness', v: `${d.tenant.scanCompleteness}%` },
          ].map((f, i) => (
            <div key={i}>
              <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, textTransform: 'uppercase', marginRight: 6 }}>{f.l}:</span>
              <span style={{ fontFamily: F.data, fontSize: 11, color: P.textMuted }}>{f.v}</span>
            </div>
          ))}
        </div>
        <div style={{ fontFamily: F.ui, fontSize: 11, color: P.textDim, marginTop: 8 }}>{d.tenant.confidenceModelBasis}</div>
      </Card>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// MAIN COMPONENT
// ═══════════════════════════════════════════════════════════════════════

const TABS = [
  { id: 'exec', label: 'Executive Summary' },
  { id: 'risk', label: 'Identity Risk' },
  { id: 'action', label: 'Action Plan' },
  { id: 'governance', label: 'Control & Governance' },
  { id: 'compliance', label: 'Compliance & Evidence' },
  { id: 'movement', label: 'Risk Movement' },
];

type FilterType = 'All' | 'Users' | 'SPNs' | 'Managed' | 'Workload';

export default function Overview() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();
  const [data, setData] = useState<TenantData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('exec');
  const [filter, setFilter] = useState<FilterType>('All');
  const [viewMode, setViewMode] = useState<'Detailed' | 'Executive'>('Detailed');
  const [drillPanel, setDrillPanel] = useState<DrillPanelState>({ open: false, title: '', filterUrl: '', identities: [], loading: false });
  const [compliancePanel, setCompliancePanel] = useState<{ open: boolean; framework: Framework | null }>({ open: false, framework: null });
  const [exportMenu, setExportMenu] = useState<{ open: boolean; framework: Framework | null; anchorRect: DOMRect | null }>({ open: false, framework: null, anchorRect: null });

  const nav: Nav = useCallback((path: string) => navigate(path), [navigate]);

  const openDrill = useCallback((title: string, filterUrl: string) => {
    setDrillPanel({ open: true, title, filterUrl, identities: [], loading: true });
    const apiUrl = filterUrl.replace(/^\/identities/, '/api/identities');
    const joiner = apiUrl.includes('?') ? '&' : '?';
    fetch(withConnection(`${apiUrl}${joiner}limit=20`))
      .then(r => r.ok ? r.json() : { identities: [] })
      .then(data => setDrillPanel(prev => ({ ...prev, identities: data.identities || [], loading: false })))
      .catch(() => setDrillPanel(prev => ({ ...prev, identities: [], loading: false })));
  }, [withConnection]);

  const openComplianceDetail = useCallback((fw: Framework) => { setCompliancePanel({ open: true, framework: fw }); }, []);
  const closeComplianceDetail = useCallback(() => { setCompliancePanel({ open: false, framework: null }); }, []);
  const openExportMenuCb = useCallback((fw: Framework, rect: DOMRect) => { setExportMenu({ open: true, framework: fw, anchorRect: rect }); }, []);
  const closeExportMenu = useCallback(() => { setExportMenu({ open: false, framework: null, anchorRect: null }); }, []);

  useEffect(() => {
    // Inject Google Fonts
    if (!document.getElementById('exec-fonts')) {
      const link = document.createElement('link');
      link.id = 'exec-fonts';
      link.rel = 'stylesheet';
      link.href = 'https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700;800&display=swap';
      document.head.appendChild(link);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    fetchTenantData(withConnection)
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, [selectedConnectionId, withConnection]);

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: P.bgPage,
        fontFamily: F.data, fontSize: 14, color: P.textMuted,
      }}>Loading...</div>
    );
  }

  if (error || !data) {
    return (
      <div style={{
        minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: P.bgPage,
        fontFamily: F.ui, fontSize: 14, color: '#ff4444',
      }}>Failed to load dashboard data: {error}</div>
    );
  }

  const d = data;
  const tier = d.riskScore.tier;
  const tierColor = getTierColor(tier);

  // Identity count based on filter
  const identityCount = filter === 'All' ? d.identities.total
    : filter === 'Users' ? d.identities.byType.users
    : filter === 'SPNs' ? d.identities.byType.servicePrincipals
    : filter === 'Managed' ? d.identities.byType.managedIdentities
    : d.identities.byType.workloadIdentities;

  const renderTab = () => {
    switch (activeTab) {
      case 'exec': return <ExecutiveSummaryTab d={d} nav={nav} openDrill={openDrill} setActiveTab={setActiveTab} openComplianceDetail={openComplianceDetail} />;
      case 'risk': return <IdentityRiskTab d={d} nav={nav} />;
      case 'action': return <ActionPlanTab d={d} nav={nav} />;
      case 'governance': return <ControlGovernanceTab d={d} nav={nav} />;
      case 'compliance': return <ComplianceEvidenceTab d={d} nav={nav} openDrill={openDrill} setActiveTab={setActiveTab} openComplianceDetail={openComplianceDetail} openExportMenu={openExportMenuCb} />;
      case 'movement': return <RiskMovementTab d={d} nav={nav} />;
      default: return null;
    }
  };

  return (
    <div style={{
      minHeight: '100vh', fontFamily: F.ui, color: P.textBright,
      background: P.bgPage,
      padding: '24px 32px',
      animation: 'execFadeIn 0.5s ease',
    }}>
      <style>{`@keyframes execFadeIn { from { opacity: 0; } to { opacity: 1; } }`}</style>

      {/* ── DATA FRESHNESS BAR ── */}
      <DataFreshnessBar tenant={d.tenant} scoring={d.scoringMethodology} />

      {/* ── HEADER ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 24, marginBottom: 24 }}>
        <ScoreRing score={d.riskScore.current} grade={d.riskScore.grade} size={80} />

        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {d.tenant.organizationLogo && (
              <img src={d.tenant.organizationLogo} alt="" style={{ height: 28, borderRadius: 4 }} />
            )}
            <div>
              <div style={{ fontFamily: F.ui, fontSize: 18, fontWeight: 700, color: P.textBright }}>{d.tenant.organizationName}</div>
              <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted }}>Identity Attack Surface Management</div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 12, marginTop: 6, alignItems: 'center' }}>
            <RiskTierBadge tier={tier} />
            <span style={{ fontFamily: F.data, fontSize: 10, color: d.riskScore.delta30d >= 0 ? '#22c55e' : '#ff4444' }}>
              {formatDelta(d.riskScore.delta30d)} vs 30d
            </span>
            <span style={{ fontFamily: F.data, fontSize: 10, color: P.textFaint }}>|</span>
            <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}>Industry: <DrillableNumber value={d.riskScore.industryAvg} label="Industry average posture" onClick={() => navigate('/identities')} /></span>
            <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}>Target: <DrillableNumber value={d.riskScore.target} label="Posture target (configurable in Settings)" onClick={() => navigate('/settings')} /></span>
            <span style={{ fontFamily: F.data, fontSize: 10, color: '#22c55e' }}>Potential: <DrillableNumber value={`+${d.riskScore.potentialGain}`} label="Potential gain from remediations" onClick={() => setActiveTab('action')} /></span>
          </div>
          <div style={{ marginTop: 4, fontFamily: F.data, fontSize: 10, color: P.textFaint }}>
            {'\u2022'} {d.tenant.cloud} {'\u2022'} <DrillableNumber value={d.tenant.subscriptions} label="View subscriptions" onClick={() => navigate('/subscriptions')} /> subs {'\u2022'} {new Date(d.tenant.lastScan).toLocaleString()}
          </div>
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', gap: 4, padding: 4, background: P.bgSubtle, borderRadius: 8, border: `1px solid ${P.borderCard}` }}>
          {(['All', 'Users', 'SPNs', 'Managed', 'Workload'] as FilterType[]).map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              fontFamily: F.data, fontSize: 10, fontWeight: 600, padding: '4px 10px', borderRadius: 6,
              border: 'none', cursor: 'pointer',
              background: filter === f ? P.accentIndigoBg : 'transparent',
              color: filter === f ? P.accentIndigo : P.textDim, transition: 'all 0.2s ease',
            }}>{f}</button>
          ))}
        </div>

        {/* Identity count — click opens drill-down panel */}
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontFamily: F.data, fontSize: 28, fontWeight: 800, color: P.textBright }}><DrillableNumber value={identityCount} label="Drill into identities" onClick={() => openDrill(`${filter} Identities`, FILTER_NAV[filter] || '/identities')} /></div>
          <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, textTransform: 'uppercase' }}>Identities</div>
          <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
            {d.identities.critical > 0 && <span style={{ fontFamily: F.data, fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'rgba(255,68,68,0.15)', color: '#ff4444', cursor: 'pointer' }}><DrillableNumber value={`CRIT ${d.identities.critical}`} label="Critical identities" onClick={() => openDrill('Critical Identities', '/identities?risk_level=critical')} /></span>}
            {d.identities.high > 0 && <span style={{ fontFamily: F.data, fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'rgba(255,140,0,0.15)', color: '#ff8c00', cursor: 'pointer' }}><DrillableNumber value={`HIGH ${d.identities.high}`} label="High risk identities" onClick={() => openDrill('High Risk Identities', '/identities?risk_level=high')} /></span>}
          </div>
        </div>

        {/* View mode */}
        <div style={{ display: 'flex', gap: 4, padding: 4, background: P.bgSubtle, borderRadius: 8, border: `1px solid ${P.borderCard}` }}>
          {(['Detailed', 'Executive'] as const).map(v => (
            <button key={v} onClick={() => setViewMode(v)} style={{
              fontFamily: F.data, fontSize: 10, fontWeight: 600, padding: '4px 10px', borderRadius: 6,
              border: 'none', cursor: 'pointer',
              background: viewMode === v ? P.accentIndigoBg : 'transparent',
              color: viewMode === v ? P.accentIndigo : P.textDim, transition: 'all 0.2s ease',
            }}>{v}</button>
          ))}
        </div>
      </div>

      {/* ── TAB BAR ── */}
      <div style={{ display: 'flex', gap: 0, borderBottom: `1px solid ${P.borderCard}`, marginBottom: 24 }}>
        {TABS.map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{
            fontFamily: F.ui, fontSize: 13, fontWeight: 500, padding: '10px 20px',
            border: 'none', cursor: 'pointer', background: 'transparent', transition: 'all 0.2s ease',
            color: activeTab === tab.id ? P.textLight : P.textDim,
            borderBottom: `2px solid ${activeTab === tab.id ? P.accentStrong : 'transparent'}`,
          }}>{tab.label}</button>
        ))}
      </div>

      {/* ── TAB CONTENT ── */}
      {renderTab()}

      {/* ── DRILL DOWN PANEL ── */}
      <DrillDownPanel
        state={drillPanel}
        onClose={() => setDrillPanel(prev => ({ ...prev, open: false }))}
        onViewAll={() => { setDrillPanel(prev => ({ ...prev, open: false })); nav(drillPanel.filterUrl); }}
      />

      {/* ── COMPLIANCE DETAIL PANEL ── */}
      <ComplianceDetailPanel
        state={compliancePanel}
        onClose={closeComplianceDetail}
        openDrill={openDrill}
        setDrillPanel={setDrillPanel}
      />

      {/* ── EXPORT MENU ── */}
      <ExportMenu state={exportMenu} onClose={closeExportMenu} />
    </div>
  );
}
