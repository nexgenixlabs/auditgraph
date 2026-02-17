/**
 * AuditGraph Enterprise Design Tokens
 * Single source of truth for the enterprise UI redesign.
 */

// ── Colors ─────────────────────────────────────────────────────────

export const COLORS = {
  brand: '#1E3A5F',
  brandLight: 'var(--accent-primary)',
  background: 'var(--bg-primary)',
  card: 'var(--bg-secondary)',
  textPrimary: 'var(--text-primary)',
  textSecondary: 'var(--text-secondary)',
  textMuted: 'var(--text-tertiary)',
  border: 'var(--border-default)',
  borderLight: 'var(--border-subtle)',
} as const;

export const RISK_COLORS = {
  critical:   { color: '#DC2626', bg: 'var(--tint-red)' },
  high:       { color: '#F97316', bg: 'var(--tint-orange)' },
  medium:     { color: '#FACC15', bg: 'var(--tint-yellow)' },
  low:        { color: '#22C55E', bg: 'var(--tint-green)' },
  info:       { color: '#3B82F6', bg: 'var(--tint-blue)' },
} as const;

export const FRAMEWORK_COLORS = {
  SOC2: '#7C3AED',
  CIS:  '#2563EB',
  HIPAA: '#DC2626',
  NIST: '#059669',
} as const;

// ── Score Thresholds ───────────────────────────────────────────────

export function scoreToColor(score: number): string {
  if (score <= 20) return '#16A34A';
  if (score <= 40) return '#84CC16';
  if (score <= 60) return '#FACC15';
  if (score <= 80) return '#F97316';
  return '#DC2626';
}

export function scoreToGrade(score: number): string {
  if (score <= 20) return 'A';
  if (score <= 40) return 'B';
  if (score <= 60) return 'C';
  if (score <= 80) return 'D';
  return 'F';
}

export function scoreToSeverity(score: number): string {
  if (score <= 20) return 'low';
  if (score <= 40) return 'moderate';
  if (score <= 60) return 'high';
  if (score <= 80) return 'very_high';
  return 'critical';
}

// ── Dashboard Tab Definitions ──────────────────────────────────────

export type DashboardTab = 'exposure' | 'credential' | 'trust' | 'usage' | 'governance' | 'platform';

export const DASHBOARD_TABS: { id: DashboardTab; label: string; description: string }[] = [
  { id: 'exposure',   label: 'Exposure & Risk',           description: 'Risk trends, anomalies, and heat maps' },
  { id: 'credential', label: 'Credential Intelligence',   description: 'Secret age, auth methods, rotation compliance' },
  { id: 'trust',      label: 'Trust & Access',            description: 'Trust relationships and effective access' },
  { id: 'usage',      label: 'Usage & Optimization',      description: 'Role usage, dormancy, and quick actions' },
  { id: 'governance', label: 'Governance & Compliance',    description: 'Compliance frameworks, remediation, conditional access' },
  { id: 'platform',   label: 'Platform & Discovery',      description: 'Cloud coverage, SOAR, platform health' },
];

// Widget-to-tab mapping
export const TAB_WIDGETS: Record<DashboardTab, string[]> = {
  exposure:   ['risk_trend_chart', 'risk_velocity_chart', 'risk_heat_map', 'risk_donut_chart', 'recent_changes', 'anomaly_alerts'],
  credential: ['credential_health', 'expiry_tracker'],
  trust:      [],  // placeholder — Phase 3
  usage:      ['role_usage_chart', 'quick_actions'],
  governance: ['compliance_scorecard', 'remediation_progress', 'sa_governance', 'conditional_access'],
  platform:   ['cloud_context_banner', 'soar_activity', 'platform_health', 'resource_overview'],
};
