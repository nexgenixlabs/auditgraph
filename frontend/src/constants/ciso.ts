/**
 * AuditGraph v3.0.4 CISO Dashboard — Design System
 *
 * Color tokens, scoring helpers, and TypeScript interfaces.
 * All dashboard components MUST use these tokens — no raw hex values.
 *
 * v3.0.2: DrillableNumber enforcement, Preview Changes panel, Create Ticket integration,
 *          bug fixes (Rules 30-32), dead button elimination (Rules 33-35).
 * v3.0.3: identityStore (real scan data), data source attribution (Rules 37-40).
 * v3.0.4: Eliminated separate remediationDiffs — role diffs embedded in
 *          remediation.changes[]. "Connect Azure" bug fixed (Rule 33/39 updated).
 */

// ─── Color Tokens ────────────────────────────────────────────────

export const COLORS = {
  // Backgrounds
  bg:           "#080c14",
  surface:      "#0f1520",
  surfaceAlt:   "#141c2b",
  surfaceHover: "#1a2438",
  border:       "#1c2740",
  borderAccent: "#2a3d5c",

  // Text
  text:         "#e2e8f0",
  textMuted:    "#64748b",
  textDim:      "#3e4f6a",

  // Semantic
  accent:       "#3b82f6",
  accentSoft:   "rgba(59,130,246,0.12)",
  danger:       "#ef4444",
  dangerSoft:   "rgba(239,68,68,0.10)",
  warning:      "#f59e0b",
  warningSoft:  "rgba(245,158,11,0.08)",
  success:      "#10b981",
  successSoft:  "rgba(16,185,129,0.10)",
  elevated:     "#f97316",
  purple:       "#8b5cf6",
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
  delta: number;
  tier: string;
  grade: string;
  industry: number;
  target: number;
  potentialGain: number;
  trend: number[];
}

export interface Projection {
  noAction: {
    score: number;
    tier: string;
    consequences: string[];
    breachImpact: string;
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
  identityIds: string[];
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
  identityIds: string[];
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
  effort: string;
  rollback: string;
  rollbackRisk: string;
  compliance: string;
  confidence: number;
  productionImpact: boolean;
  riskPerDay: number;
  affectedIdentityIds: string[];
  changes: RemediationChange[];
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
  identityIds: string[];
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

export interface IdentityRecord {
  id: string;
  displayName: string;
  upn: string;
  type: string;
  status: string;
  lastSignIn: string | null;
  riskScore: number;
  riskLevel: string;
  roles: string[];
  owner: string | null;
  groups: string[];
  createdDate: string | null;
}

/** Per-identity role change diff, embedded in remediation.changes[] (v3.0.4). */
export interface RemediationChange {
  identityId: string;
  currentRole: string;
  currentScope: string;
  proposedRole: string;
  proposedScope: string;
  riskLevel: string;
  impact: string;
  reversible: boolean;
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
  identityStore: Record<string, IdentityRecord>;
}
