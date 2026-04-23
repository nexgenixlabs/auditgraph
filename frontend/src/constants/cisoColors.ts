/**
 * CISO Dashboard — Shared Color Maps
 * Extracted from CISODashboard.tsx for reuse across section components.
 */

export const STATUS_DOT: Record<string, string> = {
  critical: '#e8465a', high: '#FF7216', moderate: '#f59e0b', low: '#22c55e', no_data: '#4a6080',
};

export const STATUS_TEXT_CLS: Record<string, string> = {
  critical: 'text-[#e8465a]', high: 'text-[#FF7216]', moderate: 'text-[#f59e0b]', low: 'text-[#22c55e]', no_data: 'text-[#4a6080]',
};

export const STATUS_LABEL: Record<string, string> = {
  critical: 'CRITICAL RISK', high: 'HIGH RISK', moderate: 'MODERATE RISK', low: 'LOW RISK', no_data: 'NO DATA',
};

export const EXPOSURE_TAG_CLS: Record<string, string> = {
  critical: 'bg-[rgba(232,70,90,0.15)] text-[#e8465a]',
  high: 'bg-[rgba(255,114,22,0.15)] text-[#FF7216]',
  moderate: 'bg-[rgba(245,158,11,0.15)] text-[#f59e0b]',
  low: 'bg-[rgba(34,197,94,0.15)] text-[#22c55e]',
};

export const VERDICT_CLS: Record<string, string> = {
  red: 'bg-[rgba(232,70,90,0.15)] text-[#e8465a]',
  orange: 'bg-[rgba(255,114,22,0.15)] text-[#FF7216]',
  amber: 'bg-[rgba(245,158,11,0.15)] text-[#f59e0b]',
  purple: 'bg-[rgba(120,100,200,0.15)] text-[#a78bfa]',
  teal: 'bg-[rgba(36,162,161,0.12)] text-[#24A2A1]',
  green: 'bg-[rgba(34,197,94,0.12)] text-[#22c55e]',
};

export const TAG_CLS: Record<string, string> = {
  red: 'bg-[rgba(232,70,90,0.15)] text-[#e8465a]',
  orange: 'bg-[rgba(255,114,22,0.15)] text-[#FF7216]',
  green: 'bg-[rgba(34,197,94,0.15)] text-[#22c55e]',
  teal: 'bg-[rgba(36,162,161,0.15)] text-[#24A2A1]',
};

export const RISK_BAR_COLOR: Record<string, string> = {
  critical: '#e8465a', high: '#FF7216', medium: '#f59e0b', low: '#22c55e',
};

export const CONFIDENCE_CLS: Record<string, string> = {
  high: 'text-[#24A2A1]', medium: 'text-[#f59e0b]', low: 'text-[#4a6080]',
};

export const BLAST_SEVERITY_CLS: Record<string, string> = {
  critical: 'bg-[rgba(232,70,90,0.15)] text-[#e8465a]',
  high: 'bg-[rgba(232,70,90,0.15)] text-[#e8465a]',
  medium: 'bg-[rgba(245,158,11,0.12)] text-[#f59e0b]',
  low: 'bg-[rgba(36,162,161,0.12)] text-[#24A2A1]',
};

export const SEVERITY_BG: Record<string, string> = {
  critical: 'bg-[rgba(232,70,90,0.12)]',
  high: 'bg-[rgba(255,114,22,0.12)]',
  medium: 'bg-[rgba(245,158,11,0.1)]',
  low: 'bg-[rgba(34,197,94,0.1)]',
};

export const SEVERITY_TEXT: Record<string, string> = {
  critical: 'text-[#e8465a]',
  high: 'text-[#FF7216]',
  medium: 'text-[#f59e0b]',
  low: 'text-[#22c55e]',
};

export const BORDER_ACCENT: Record<string, string> = {
  red: 'border-l-[#e8465a]',
  yellow: 'border-l-[#f59e0b]',
  green: 'border-l-[#22c55e]',
};

// ── Posture v3.1 Tokens ──────────────────────────────────────

export const POSTURE_STATUS_COLOR: Record<string, string> = {
  STRONG: '#24A2A1',
  MODERATE: '#f59e0b',
  ELEVATED_RISK: '#FF7216',
  WEAK: '#e8465a',
  CRITICAL_EXPOSURE: '#e8465a',
};

export const POSTURE_STATUS_BORDER: Record<string, string> = {
  STRONG: 'border-l-[#24A2A1]',
  MODERATE: 'border-l-[#f59e0b]',
  ELEVATED_RISK: 'border-l-[#FF7216]',
  WEAK: 'border-l-[#e8465a]',
  CRITICAL_EXPOSURE: 'border-l-[#e8465a]',
};

export const POSTURE_STATUS_LABEL: Record<string, string> = {
  STRONG: 'Strong',
  MODERATE: 'Moderate',
  ELEVATED_RISK: 'Elevated Risk',
  WEAK: 'Weak',
  CRITICAL_EXPOSURE: 'Critical Exposure',
};

export const POSTURE_STATUS_TEXT: Record<string, string> = {
  STRONG: 'text-[#24A2A1]',
  MODERATE: 'text-[#f59e0b]',
  ELEVATED_RISK: 'text-[#FF7216]',
  WEAK: 'text-[#e8465a]',
  CRITICAL_EXPOSURE: 'text-[#e8465a]',
};

/** Derive 4-tier posture band label from a 0-100 score. */
export function postureBandFromScore(score: number): { label: string; color: string; textCls: string } {
  if (score >= 85) return { label: 'Strong', color: '#24A2A1', textCls: 'text-[#24A2A1]' };
  if (score >= 70) return { label: 'Moderate', color: '#f59e0b', textCls: 'text-[#f59e0b]' };
  if (score >= 50) return { label: 'Elevated Risk', color: '#FF7216', textCls: 'text-[#FF7216]' };
  return { label: 'Critical Exposure', color: '#e8465a', textCls: 'text-[#e8465a]' };
}

export const POSTURE_CONFIDENCE_COLOR: Record<string, string> = {
  high: '#24A2A1',
  medium: '#f59e0b',
  low: '#4a6080',
};

/** User-facing confidence labels: low→Improving, medium→Good, high→High */
export const CONFIDENCE_DISPLAY_LABEL: Record<string, string> = {
  high: 'High',
  medium: 'Good',
  low: 'Improving',
};

/** Shared tooltip for all confidence labels in the CISO / Executive Posture area */
export const CONFIDENCE_TOOLTIP = 'Confidence improves as more data sources activate. Currently log-independent mode.';
