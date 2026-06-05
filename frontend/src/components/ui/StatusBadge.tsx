import React from 'react';
import { SEVERITY_HEX } from '../../constants/riskScoring';

type BadgeVariant = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'warning' | 'neutral';
type BadgeSize = 'xs' | 'sm' | 'md';

interface StatusBadgeProps {
  variant: BadgeVariant;
  children: React.ReactNode;
  /** Show a dot indicator before the text */
  dot?: boolean;
  /** Visual size. Default 'sm' matches the original badge spec. */
  size?: BadgeSize;
  /** Pill-shaped (fully rounded) instead of the default 4px radius. */
  pill?: boolean;
  className?: string;
}

const SIZE_STYLE: Record<BadgeSize, React.CSSProperties> = {
  xs: { fontSize: 9,  padding: '1px 6px', gap: 3 },
  sm: { fontSize: 11, padding: '2px 8px', gap: 4 },
  md: { fontSize: 12, padding: '3px 10px', gap: 5 },
};

// Severity colors pulled from the canonical SEVERITY_HEX map so all badge
// instances render the same red/orange/yellow/green that charts and the
// design tokens use. The previous hand-rolled hex set (#f87171 / #fb923c /
// #fbbf24 / #4ade80) was a 4th independent palette and is now removed.
const VARIANTS: Record<BadgeVariant, { bg: string; color: string }> = {
  critical: { bg: 'var(--tint-red)',    color: SEVERITY_HEX.critical },
  high:     { bg: 'var(--tint-orange)', color: SEVERITY_HEX.high },
  medium:   { bg: 'var(--tint-yellow)', color: SEVERITY_HEX.medium },
  low:      { bg: 'var(--tint-green)',  color: SEVERITY_HEX.low },
  info:     { bg: 'var(--tint-blue)',   color: SEVERITY_HEX.info },
  success:  { bg: 'var(--tint-green)',  color: SEVERITY_HEX.low },
  warning:  { bg: 'var(--tint-orange)', color: SEVERITY_HEX.high },
  neutral:  { bg: 'var(--bg-elevated)', color: 'var(--text-tertiary)' },
};

/**
 * Status Badge — compact severity/status indicator.
 *
 * Spec: 4px border-radius, 11px font, uppercase, 600 weight.
 * Zero-value rule: "Unknown" gets variant="neutral" (no color).
 */
export default function StatusBadge({ variant, children, dot, size = 'sm', pill = false, className = '' }: StatusBadgeProps) {
  const v = VARIANTS[variant] || VARIANTS.neutral;
  const sizeStyle = SIZE_STYLE[size];

  return (
    <span
      className={`status-badge ${className}`}
      style={{
        backgroundColor: v.bg,
        color: v.color,
        borderRadius: pill ? 9999 : undefined,
        ...sizeStyle,
      }}
    >
      {dot && (
        <span
          className="w-1.5 h-1.5 rounded-full flex-shrink-0"
          style={{ backgroundColor: v.color }}
        />
      )}
      {children}
    </span>
  );
}
