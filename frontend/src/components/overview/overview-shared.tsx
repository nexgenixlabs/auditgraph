import React, { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { formatDate, formatRelativeTime, formatCompleteness, formatFrequency } from '../../utils/displayHelpers';

// ═══════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface DrilldownItem { label: string; impact: 'critical' | 'high' | 'medium' | 'low' }
export interface PillarData { name: string; score: number; weight: number; detail: string; drilldown: DrilldownItem[] }
export interface RiskDriver { label: string; impact: 'critical' | 'high' | 'medium' | 'low'; pillar: string }
export interface BlastRadius { identities: number; subscriptions: number; workloads: number }
export interface Remediation {
  rank: number; action: string; description: string; gain: number;
  complexity: 'LOW' | 'MEDIUM' | 'HIGH'; affectedIds: number; confidence?: number | null;
  estimatedDays: number; automation: 'full' | 'partial' | 'manual';
  blastRadius: BlastRadius; rollbackSafety: 'safe' | 'requires-validation' | 'irreversible';
  impactsProduction: boolean;
  type: 'identity-remediation' | 'system-action' | 'configuration';
}
export interface ComplianceControl {
  controlId: string; name: string;
  status: 'pass' | 'warn' | 'fail';
  severity: 'critical' | 'high' | 'medium' | 'low';
  metric: string; value: number; passThreshold: string;
  detail: string; drilldownUrl: string | null; weight: number;
  evidenceIdentities: Array<{ id: number; identity_id: string; display_name: string; risk_level: string; risk_score: number; identity_category: string; reason: string }>;
  evidenceCount: number;
}
export interface Framework {
  name: string; passed: number; total: number; pct: number;
  failingIdentities: number; controlMappingSource: string;
  coverageTrend30d: number | null;
  controls: ComplianceControl[];
  key: string;
  category: string;
}
export interface ScoringMethodology { url: string; label: string; summary: string }
export interface GovMetric { label: string; value: number; target: number; icon: string; trend30d: number | null; configured: boolean }
export interface PolicyGap { label: string; count: number; severity: 'critical' | 'high' | 'medium' | 'low' }
export interface TrendRow { label: string; previous: number; current: number; direction: 'up' | 'down' | 'same' }
export interface AffectedWorkload {
  name: string; type: string; region: string; exposedIdentities: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
}
export interface ComponentAvg { name: string; score: number; max: number }
export interface SystemAction { id: string; label: string; status: 'pending' | 'completed' | 'in-progress' | 'failed'; description: string }
export interface ScoringContent {
  overview: string; scoreDirection: string;
  pillars: { name: string; weight: number; description: string }[];
  compositeFormula: string;
  tierThresholds: { tier: string; range: string; description: string }[];
}

export type Nav = (path: string) => void;

// Navigation target mapping for governance metrics
export const GOV_NAV: Record<string, string> = {
  'Ownership Coverage': '/service-accounts',
  'PIM Coverage': '/identities',
  'Privileged Under Review': '/access-reviews',
  'Access Reviews Done': '/access-reviews',
};

// Navigation target mapping for KPI cards
export const KPI_NAV: Record<string, string> = {
  'Privileged NHIs': '/workload-identities',
  'Dormant Privileged': '/identities?activity_status=stale',
  'Subscription Access': '/identities',
  'RBAC Modifiers': '/identities',
};

// Navigation target mapping for risk movement rows
export const MOVE_NAV: Record<string, string> = {
  'Critical Identities': '/identities?risk_level=critical',
  'High-Risk Identities': '/identities?risk_level=high',
  'Total Identities': '/identities',
  'New Identities': '/identities',
  'Removed': '/identities',
};

// Navigation target mapping for pillar scores
export const PILLAR_NAV: Record<string, string> = {
  'Effective Privilege': '/identities?risk_level=critical',
  'Credential Risk': '/spns',
  'Trust & Federation': '/identities?identity_category=guest',
  'Usage Dormancy': '/identities?activity_status=stale',
  'Ownership Governance': '/service-accounts',
  'External Exposure': '/identities',
};

// Navigation target mapping for workload exposure metrics
export const WORKLOAD_NAV: Record<string, string> = {
  'Avg Score': '/workload-identities',
  'Can Escalate': '/identities?risk_level=critical',
  'Orphaned': '/service-accounts',
  'Zombies': '/identities?activity_status=stale',
  'Cross-Sub': '/identities',
  'Tenant Scope': '/identities',
};

// Navigation target mapping for lifecycle states
export const LIFECYCLE_NAV: Record<string, string> = {
  'Active': '/identities?activity_status=active',
  'Stale': '/identities?activity_status=stale',
  'Dormant': '/identities?activity_status=inactive',
  'Blind': '/workload-identities',
};

// Navigation target mapping for policy gaps
export const POLICY_GAP_NAV: Record<string, string> = {
  'Privilege outside PIM': '/identities?risk_level=critical',
};

// Filter to identity_category mapping for header drill
export const FILTER_NAV: Record<string, string> = {
  All: '/identities',
  Users: '/identities?identity_category=human_user',
  SPNs: '/identities?identity_category=service_principal',
  Managed: '/identities?identity_category=managed_identity_system',
  Workload: '/workload-identities',
};

export interface TenantData {
  insufficientData: boolean;
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
    current: number; grade: string; tier: string; previous30d: number | null; delta30d: number | null;
    industryAvg: number | null; target: number; potentialGain: number;
    projectedNoAction: number | null; projectedRemediated: number;
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

export type FilterType = 'All' | 'Users' | 'SPNs' | 'Managed' | 'Workload';

export interface DrillPanelState { open: boolean; title: string; filterUrl: string; identities: any[]; loading: boolean }

// ═══════════════════════════════════════════════════════════════════════
// STYLE CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

export const F = { ui: '"Inter", -apple-system, sans-serif', data: '"JetBrains Mono", monospace' };

export const P = {
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
// DATA CONSTANTS
// ═══════════════════════════════════════════════════════════════════════

export const PILLAR_NAMES: Record<string, string> = {
  effective_privilege: 'Effective Privilege',
  credential_risk: 'Credential Risk',
  trust_federation: 'Trust & Federation',
  usage_dormancy: 'Usage Dormancy',
  ownership_governance: 'Ownership Governance',
  external_exposure: 'External Exposure',
};
export const PILLAR_ORDER = ['effective_privilege', 'credential_risk', 'trust_federation', 'usage_dormancy', 'ownership_governance', 'external_exposure'];

// ═══════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

export function getTier(score: number): string {
  if (score === 0) return 'No Data';
  if (score <= 40) return 'Critical';
  if (score <= 60) return 'Elevated';
  if (score <= 80) return 'Controlled';
  return 'Resilient';
}
export function getGrade(score: number): string {
  if (score === 0) return '\u2014';
  if (score <= 20) return 'F';
  if (score <= 40) return 'D';
  if (score <= 60) return 'C';
  if (score <= 80) return 'B';
  return 'A';
}
export function getTierColor(tier: string): string {
  const m: Record<string, string> = { 'No Data': '#5a6f96', Critical: '#ff4444', Elevated: '#ff8c00', Controlled: '#eab308', Resilient: '#22c55e' };
  return m[tier] || '#64748b';
}
export function getTierBg(tier: string): string {
  const m: Record<string, string> = { 'No Data': 'rgba(90,111,150,0.12)', Critical: 'rgba(255,68,68,0.15)', Elevated: 'rgba(255,140,0,0.15)', Controlled: 'rgba(234,179,8,0.15)', Resilient: 'rgba(34,197,94,0.15)' };
  return m[tier] || 'rgba(255,255,255,0.05)';
}
export function getPillarColor(score: number): string {
  if (score >= 80) return '#ff4444';
  if (score >= 50) return '#ff8c00';
  if (score >= 20) return '#eab308';
  return '#22c55e';
}
export function getSeverityColor(severity: string): string {
  const m: Record<string, string> = { critical: '#ff4444', high: '#ff8c00', medium: '#eab308', low: '#22c55e' };
  return m[severity] || '#64748b';
}
export function getAutomationConfig(level: string) {
  const m: Record<string, { label: string; color: string }> = {
    full: { label: 'Auto', color: '#22c55e' },
    partial: { label: 'Semi-Auto', color: '#eab308' },
    manual: { label: 'Manual', color: '#ff8c00' },
  };
  return m[level] || m.manual;
}
export function getRollbackConfig(safety: string) {
  const m: Record<string, { label: string; color: string; icon: string }> = {
    safe: { label: 'Safe to rollback', color: '#22c55e', icon: '\u21A9' },
    'requires-validation': { label: 'Requires manual validation', color: '#eab308', icon: '\u26A0' },
    irreversible: { label: 'Cannot be undone', color: '#ff4444', icon: '\u2715' },
  };
  return m[safety] || m['requires-validation'];
}
export function getRiskPerDay(gain: number, days: number): string {
  if (!days || days === 0) return '\u2014';
  return (gain / days).toFixed(1);
}
export function formatTrend(value: number | null) {
  if (value === null || value === undefined) return { text: 'Initial assessment', color: P.textDim };
  if (value === 0) return { text: '\u2014 unchanged', color: P.textDim };
  if (value > 0) return { text: `\u2191 +${value}%`, color: '#22c55e' };
  return { text: `\u2193 ${value}%`, color: '#ff4444' };
}
export function formatDelta(value: number): string {
  if (value > 0) return `+${value}`;
  return `${value}`;
}
export function getMaturityLevel(score: number, configured = true): string {
  if (!configured) return 'Not Assessed';
  if (score <= 20) return 'Ad-hoc';
  if (score <= 40) return 'Developing';
  if (score <= 60) return 'Operational';
  if (score <= 80) return 'Managed';
  return 'Optimized';
}
export function getMaturityColor(level: string): string {
  const m: Record<string, string> = { 'Ad-hoc': '#ff4444', Developing: '#ff8c00', Operational: '#eab308', Managed: '#22c55e', Optimized: '#3b82f6', 'Not Assessed': '#475569' };
  return m[level] || '#64748b';
}
export function getProductionExposurePct(affected: number, total: number): number {
  if (!total || total === 0) return 0;
  return Math.round((affected / total) * 100);
}
export function getCompletenessColor(pct: number): string {
  if (pct === 0) return '#5a6f96';
  if (pct >= 95) return '#22c55e';
  if (pct >= 80) return '#eab308';
  return '#ff4444';
}
export function getTimeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function detailToString(key: string, detail: Record<string, number>): string {
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

export function detailToDrilldown(key: string, detail: Record<string, number>): DrilldownItem[] {
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

// ═══════════════════════════════════════════════════════════════════════
// REUSABLE COMPONENTS
// ═══════════════════════════════════════════════════════════════════════

export function ScoreRing({ score, grade, size = 110 }: { score: number; grade: string; size?: number }) {
  const isNoData = score === 0;
  const strokeWidth = Math.max(4, Math.round(size * 0.07));
  const padding = Math.round(size * 0.05);
  const r = (size / 2) - strokeWidth - padding;
  const circ = 2 * Math.PI * r;
  const offset = isNoData ? circ : circ * (1 - score / 100);
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
      style={{ filter: isNoData ? undefined : `drop-shadow(0 0 8px ${color}55)` }}>
      <circle cx={cx} cy={cy} r={r} fill="none"
        stroke={P.bgActive} strokeWidth={strokeWidth} />
      <circle cx={cx} cy={cy} r={r} fill="none"
        stroke={color} strokeWidth={strokeWidth}
        strokeDasharray={circ} strokeDashoffset={offset}
        strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`}
        style={{ transition: 'stroke-dashoffset 1.5s ease' }} />
      <text x={cx} y={isNoData ? cy : scoreY}
        textAnchor="middle" dominantBaseline="central"
        style={{ fontFamily: F.data, fontSize: isNoData ? gradeFontSize : scoreFontSize, fontWeight: isNoData ? 600 : 800, fill: isNoData ? P.textDim : P.textBright }}>
        {isNoData ? 'NO DATA' : score.toFixed(1)}
      </text>
      {!isNoData && (
        <text x={cx} y={gradeY}
          textAnchor="middle" dominantBaseline="central"
          style={{ fontFamily: F.data, fontSize: gradeFontSize, fill: P.textMuted }}>
          {grade}
        </text>
      )}
    </svg>
  );
}

export function RiskTierBadge({ tier }: { tier: string }) {
  return (
    <span style={{
      display: 'inline-block', padding: '4px 14px', borderRadius: 6,
      fontFamily: F.data, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1.5,
      color: getTierColor(tier), background: getTierBg(tier),
    }}>{tier}</span>
  );
}

export function AutomationBadge({ level }: { level: string }) {
  const c = getAutomationConfig(level);
  return (
    <span style={{
      fontFamily: F.data, fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
      color: c.color, background: `${c.color}1f`, border: `1px solid ${c.color}33`,
    }}>{c.label}</span>
  );
}

export function RollbackBadge({ safety }: { safety: string }) {
  const c = getRollbackConfig(safety);
  return (
    <span style={{
      fontFamily: F.data, fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
      color: c.color, background: `${c.color}1a`, border: `1px solid ${c.color}33`,
    }}>{c.icon} {c.label}</span>
  );
}

export function SeverityDot({ severity }: { severity: string }) {
  return <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: getSeverityColor(severity), marginRight: 8, flexShrink: 0 }} />;
}

export function MiniProgressBar({ value, max = 100, color, height = 4 }: { value: number; max?: number; color: string; height?: number }) {
  return (
    <div style={{ width: '100%', height, borderRadius: height / 2, background: P.track }}>
      <div style={{ width: `${Math.min(100, (value / max) * 100)}%`, height: '100%', borderRadius: height / 2, background: color, transition: 'width 0.8s ease' }} />
    </div>
  );
}

export function CircularGauge({ value, size = 36, strokeWidth = 3, color }: { value: number; size?: number; strokeWidth?: number; color: string }) {
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

export function SparklineChart({ data, width = 200, height = 40, color }: { data: { day: number; score: number }[]; width?: number; height?: number; color: string }) {
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

export function RadarChart({ pillars, size = 200, onLabelClick }: { pillars: PillarData[]; size?: number; onLabelClick?: (i: number) => void }) {
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

export function Card({ children, style, glow }: { children: React.ReactNode; style?: React.CSSProperties; glow?: boolean }) {
  return (
    <div style={{
      background: P.bgCard, border: `1px solid ${P.borderCard}`,
      borderRadius: 12, padding: 20, backdropFilter: P.backdrop,
      ...(glow ? { boxShadow: P.glow } : {}),
      ...style,
    }}>{children}</div>
  );
}

export function SectionTitle({ children, right }: { children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
      <span style={{ fontFamily: F.data, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 2, color: P.textMuted }}>{children}</span>
      {right}
    </div>
  );
}

export function TooltipWrap({ content, children }: { content: string; children: React.ReactNode }) {
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

export function TrendArrow({ value }: { value: number | null }) {
  const t = formatTrend(value);
  return <span style={{ fontFamily: F.data, fontSize: 10, fontWeight: 600, color: t.color }}>{t.text}</span>;
}

export function DataFreshnessBar({ tenant, scoring }: { tenant: TenantData['tenant']; scoring: TenantData['scoringMethodology'] }) {
  const [showTip, setShowTip] = useState(false);
  return (
    <div style={{
      background: P.bgHover, borderBottom: `1px solid ${P.divider}`,
      padding: '6px 28px', display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      fontFamily: F.data, fontSize: 10, color: P.textDim, marginBottom: 16,
    }}>
      <div style={{ display: 'flex', gap: 4, alignItems: 'center', flexWrap: 'wrap' }}>
        <span>Snapshot coverage: <span style={{ color: P.textMuted, fontWeight: 600 }}>{tenant.scanCoverage}%</span> subs</span>
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

export function ProductionBadge() {
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

export function MaturityBadge({ level }: { level: string }) {
  const color = getMaturityColor(level);
  return (
    <span style={{
      display: 'inline-block', padding: '4px 14px', borderRadius: 6,
      fontFamily: F.data, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1,
      color, background: `${color}1f`, border: `1px solid ${color}40`,
    }}>{level}</span>
  );
}

export function SystemActionChip({ action, onTrigger }: { action: SystemAction; onTrigger?: () => void }) {
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

export function DrillableNumber({ value, label, onClick }: { value: number | string; label?: string; onClick?: () => void }) {
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

export function NarrativeBanner({ narrative, exposure, tier, nav }: { narrative: string; exposure: TenantData['executiveSummary']['businessExposure']; tier: string; nav: Nav }) {
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

export function WorkloadTable({ workloads }: { workloads: AffectedWorkload[] }) {
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

export function DrillDownPanel({ state, onClose, onViewAll }: { state: DrillPanelState; onClose: () => void; onViewAll: () => void }) {
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

export function ComplianceDetailPanel({ state, onClose, openDrill, setDrillPanel }: {
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
            <div style={{ fontFamily: F.ui, fontSize: 13, color: P.textDim, padding: 20, textAlign: 'center' }}>No controls data available. Capture a snapshot to populate compliance controls.</div>
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

export function ExportMenu({ state, onClose }: { state: { open: boolean; framework: Framework | null; anchorRect: DOMRect | null }; onClose: () => void }) {
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

export function ComplianceFrameworkCard({ fw, onOpenDetail, onOpenExport, onDrillFailing }: {
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
