/**
 * AuditGraph — Obsidian Command Design Tokens
 * Single source of truth for the enterprise UI.
 */

// ── Colors ─────────────────────────────────────────────────────────

export const COLORS = {
  brand: '#06090f',
  brandLight: 'var(--accent-primary)',
  bgDeep: 'var(--bg-deep)',
  bgSurface: 'var(--bg-surface)',
  bgRaised: 'var(--bg-raised)',
  bgElevated: 'var(--bg-elevated)',
  // Legacy aliases
  background: 'var(--bg-surface)',
  card: 'var(--bg-raised)',
  elevated: 'var(--bg-elevated)',
  textPrimary: 'var(--text-primary)',
  textSecondary: 'var(--text-secondary)',
  textMuted: 'var(--text-tertiary)',
  border: 'var(--border-default)',
  borderLight: 'var(--border-subtle)',
  borderStrong: 'var(--border-strong)',
  borderFocus: 'var(--border-focus)',
  accentPrimary: 'var(--accent-primary)',
  accentSuccess: 'var(--accent-success)',
  accentWarning: 'var(--accent-warning)',
  accentDanger: 'var(--accent-danger)',
} as const;

export const RISK_COLORS = {
  critical: { color: 'var(--accent-danger)',  bg: 'var(--tint-red)' },
  high:     { color: 'var(--accent-warning)', bg: 'var(--tint-orange)' },
  medium:   { color: '#fbbf24',               bg: 'var(--tint-yellow)' },
  low:      { color: 'var(--accent-success)',  bg: 'var(--tint-green)' },
  info:     { color: 'var(--accent-primary)',  bg: 'var(--tint-blue)' },
} as const;

export const FRAMEWORK_COLORS = {
  SOC2:  '#7C3AED',
  CIS:   '#2563EB',
  HIPAA: '#DC2626',
  NIST:  '#059669',
} as const;

// ── Score Thresholds ───────────────────────────────────────────────

export function scoreToColor(score: number): string {
  if (score <= 20) return '#10b981';
  if (score <= 40) return '#84cc16';
  if (score <= 60) return '#fbbf24';
  if (score <= 80) return '#f59e0b';
  return '#dc2626';
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

// ── Identity Type & Cloud Brand Colors ────────────────────────────

export const IDENTITY_TYPE_COLORS = {
  human: '#3B82F6',
  nonHuman: '#A855F7',
  guest: '#F59E0B',
  privileged: '#EF4444',
} as const;

export const CLOUD_BRAND = {
  azure: '#2563EB',
  aws: '#FF9900',
  gcp: '#34A853',
} as const;

// ── Sidebar Section Colors ────────────────────────────────────────

export const SECTION_COLORS = {
  commandCenter: '#2563eb',
  identity:      '#8b5cf6',
  governance:    '#0891b2',
  remediation:   '#16a34a',
  dataSecurity:  '#ea580c',
  compliance:    '#ca8a04',
  operations:    '#64748b',
} as const;
