/**
 * AuditGraph v3.0.5 CISO Dashboard — Design System
 *
 * Color tokens, scoring helpers, and TypeScript interfaces.
 * All dashboard components MUST use these tokens — no raw hex values.
 *
 * v3.0.2: DrillableNumber enforcement, Preview Changes panel, Create Ticket integration,
 *          bug fixes (Rules 30-32), dead button elimination (Rules 33-35).
 * v3.0.5: MAJOR ARCHITECTURE FIX — removed all invented schema fields
 *          (identityStore, identityIds, changes[], affectedIdentityIds).
 *          Dashboard tenantData contains ONLY summary data. Drill-downs
 *          navigate to /identities with filter params. Preview Changes
 *          fetches from remediation detail API on demand.
 */

// ─── Color Tokens ────────────────────────────────────────────────

export const COLORS = {
  // Backgrounds — Obsidian Command aligned
  bg:           "#06090f",     // Page background — deepest layer
  surface:      "#0c1220",     // Card background — surface
  surfaceAlt:   "#111a2e",     // Nested card / expandable row — raised
  surfaceHover: "#162038",     // Hover state on interactive cards — elevated
  border:       "#1e2d4a",     // Default border
  borderAccent: "#2a3f66",     // Hover/active border — strong

  // Text — WCAG AA on #0c1220
  text:         "#e8ecf4",     // Primary text — headings, values
  textSecondary:"#8b9dc3",     // Labels, descriptions — secondary
  textMuted:    "#5a6f96",     // Decorative, timestamps — tertiary
  textDim:      "#3d5078",     // Disabled/inactive — muted

  // Semantic
  accent:       "#2563eb",
  accentSoft:   "rgba(37,99,235,0.12)",
  danger:       "#dc2626",
  dangerSoft:   "rgba(220,38,38,0.12)",
  warning:      "#f59e0b",
  warningSoft:  "rgba(245,158,11,0.10)",
  success:      "#10b981",
  successSoft:  "rgba(16,185,129,0.12)",
  elevated:     "#f97316",
  purple:       "#8b5cf6",

  // Score Triad (v4.0)
  hiri:         "#f97316",     // HIRI — orange
  nhiri:        "#8b5cf6",     // NHIRI (Phantom) — purple
  gei:          "#2563eb",     // GEI — blue (matches accent)
};

// ─── Scoring Helpers ─────────────────────────────────────────────

export function getTierColor(tier: string): string {
  switch (tier) {
    case "CRITICAL":   return COLORS.danger;
    case "ELEVATED":   return COLORS.elevated;
    case "CONTROLLED": return COLORS.warning;
    case "RESILIENT":  return COLORS.success;
    default:           return COLORS.textMuted;
  }
}

export function getScoreColor(score: number): string {
  if (score >= 80) return COLORS.success;
  if (score >= 60) return COLORS.warning;
  if (score >= 40) return COLORS.elevated;
  return COLORS.danger;
}

export function getPillarColor(pillarScore: number): string {
  if (pillarScore >= 80) return COLORS.danger;
  if (pillarScore >= 50) return COLORS.warning;
  if (pillarScore >= 20) return COLORS.elevated;
  return COLORS.success;
}

export function getTier(score: number): string {
  if (score >= 80) return "RESILIENT";
  if (score >= 60) return "CONTROLLED";
  if (score >= 40) return "ELEVATED";
  return "CRITICAL";
}

export function getGrade(score: number): string {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 55) return "C";
  if (score >= 35) return "D";
  return "F";
}

export function getSemanticColor(key: string): string {
  return (COLORS as Record<string, string>)[key] || COLORS.textMuted;
}

// ─── TypeScript Interfaces ───────────────────────────────────────

export interface TenantMeta {
  id: string;
  name: string;
  organizationName: string;
  organizationLogo: string | null;
  cloud: string;
  subscriptions: number;
  identityCount: number;
  lastScan: string;
  scanDuration: number;
  scanCompleteness: number;
  scanConfidence: string;
  sources: string[];
  isolationGuarantee: string;
}

export interface RiskScore {
  current: number;
  previous: number;
  delta: number | null;
  tier: string;
  grade: string;
  industry: number | null;
  target: number;
  potentialGain: number;
  trend: number[];
}

export interface Projection {
  noAction: {
    score: number | null;
    tier: string | null;
    consequences: string[];
    breachImpact: string | null;
  };
  remediated: {
    score: number;
    tier: string;
    actions: string[];
    breachImpact: string;
  };
}

export interface DeltaChange {
  icon: string;
  label: string;
  value: string;
  color: string;
}

export interface IdentityBreakdownItem {
  type: string;
  count: number;
  percentage: number;
  color: string;
}

export interface Pillar {
  name: string;
  score: number;
  weight: number;
  detail: string;
  identityCount: number;
  subMetrics: { name: string; value: number; max: number }[];
}

export interface BlastRadius {
  highRisk: number;
  lowRisk: number;
  orphaned: number;
  productionWorkloads: number;
  categories: { name: string; score: number; color: string }[];
}

export interface GhostAccounts {
  total: number;
  privileged: number;
  nonPrivileged: number;
  roles: { role: string; scope: string; count: number }[];
  complianceImpact: string[];
  lastDetected: string;
}

export interface KPIs {
  privilegedRoles: { value: number; subtitle: string };
  dormantPrivileged: { value: number; subtitle: string };
  ghostAccounts: { value: number; subtitle: string };
  subscriptionAccess: { value: number; subtitle: string };
  rbacModifiers: { value: number; subtitle: string };
}

export interface Remediation {
  id: string;
  type: string;
  title: string;
  subtitle: string;
  gain: number;
  projectedScore: string;
  status: string;
  automation: string;
  risk: string;
  color: string;
  affected: string;
  effort: string | null;
  rollback: string | null;
  rollbackRisk: string | null;
  compliance: string | null;
  confidence: number | null;
  productionImpact: boolean;
  riskPerDay: number | null;
}

export interface GovernanceMetric {
  label: string;
  value: string;
  target: string;
  status: string;
  icon: string;
}

export interface ControlFailureGroup {
  type: string;
  items: { label: string; count: number; color: string }[];
}

export interface Governance {
  effectivenessScore: number;
  effectivenessTier: string;
  maturityLevel: string;
  metrics: GovernanceMetric[];
  controlFailures: ControlFailureGroup[];
  setupCompletion: { configured: number; total: number };
}

export interface ComplianceControl {
  id: string;
  name: string;
  status: string;
  severity: string;
  evidence: string;
  recommendation: string;
  identityCount: number;
  detectedAt: string;
  lastEvaluatedAt: string;
}

export interface ComplianceFramework {
  id: string;
  name: string;
  type: string;
  score: number;
  totalControls: number;
  failedControls: number;
  status: string;
  trend: number;
  identityImpactCount: number;
  controls: ComplianceControl[];
}

export interface ComplianceData {
  frameworks: ComplianceFramework[];
  maturity: { preventive: number; detective: number; compensating: number; missing: number };
  progress: { remediation: number; iaGovernance: number };
}

export interface RiskMovementChange {
  label: string;
  before: number;
  after: number;
  direction: string;
}

export interface TicketingIntegration {
  configured: boolean;
  provider: string | null; // 'jira' | 'servicenow' | 'azure_devops'
  projectKey: string | null;
  defaultAssignee: string | null;
  jira: {
    cloudUrl: string | null;
    projectId: string | null;
    issueTypeId: string | null;
    priorityMapping: Record<string, string>;
  } | null;
}

export interface RiskMovement {
  trajectory: number[];
  changes: RiskMovementChange[];
  mostChanged: { name: string; score: number; category: string };
  scanMeta: {
    frequency: string;
    lastRun: string;
    sources: string;
    duration: string;
    completeness: string;
  };
}

// ─── AGIRS Types ─────────────────────────────────────────────────

export interface HIRIBreakdown {
  score: number;
  human_count: number;
  h1_ghost: number;
  h2_dormant_priv: number;
  h3_over_priv: number;
  h4_ext_guest: number;
  h5_zombie: number;
}

export interface NHIRIBreakdown {
  score: number;
  nhi_count: number;
  phantom_breakdown: {
    orphaned: number;
    dormant: number;
    zombie_nhi: number;
    expired_creds: number;
    ownerless_apps: number;
  };
}

export interface GEIBreakdown {
  score: number;
  components: Array<{ name: string; score: number; configured: boolean }>;
}

export interface DangerousIdentity {
  id: number;
  display_name: string;
  identity_category: string;
  blast_radius_score: number;
  risk_score: number;
  tier: string;
  key_risk_factors: string[];
  navigateTo?: string;
}

export interface AGIRSData {
  agirs: { score: number; tier: string; delta: number | null } | null;
  hiri: HIRIBreakdown | null;
  nhiri: NHIRIBreakdown | null;
  gei: GEIBreakdown | null;
  dangerous_identities: DangerousIdentity[];
  previous: { agirs: number | null; hiri: number | null; nhiri: number | null; gei: number | null } | null;
}

export interface TenantData {
  tenant: TenantMeta;
  riskScore: RiskScore;
  projection: Projection;
  ghostAccounts: GhostAccounts;
  deltaChanges: DeltaChange[];
  identityBreakdown: IdentityBreakdownItem[];
  pillars: Pillar[];
  blastRadius: BlastRadius;
  kpis: KPIs;
  remediations: Remediation[];
  governance: Governance;
  compliance: ComplianceData;
  riskMovement: RiskMovement;
  ticketingIntegration: TicketingIntegration;
  agirs: AGIRSData;
}
