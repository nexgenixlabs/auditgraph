import React from 'react';

type BadgeVariant = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'warning' | 'neutral';

interface StatusBadgeProps {
  variant: BadgeVariant;
  children: React.ReactNode;
  /** Show a dot indicator before the text */
  dot?: boolean;
  className?: string;
}

const VARIANTS: Record<BadgeVariant, { bg: string; color: string }> = {
  critical: { bg: 'var(--tint-red)',    color: '#f87171' },
  high:     { bg: 'var(--tint-orange)', color: '#fb923c' },
  medium:   { bg: 'var(--tint-yellow)', color: '#fbbf24' },
  low:      { bg: 'var(--tint-green)',  color: '#4ade80' },
  info:     { bg: 'var(--tint-blue)',   color: '#60a5fa' },
  success:  { bg: 'var(--tint-green)',  color: '#4ade80' },
  warning:  { bg: 'var(--tint-orange)', color: '#fb923c' },
  neutral:  { bg: 'var(--bg-elevated)', color: 'var(--text-tertiary)' },
};

/**
 * Status Badge — compact severity/status indicator.
 *
 * Spec: 4px border-radius, 11px font, uppercase, 600 weight.
 * Zero-value rule: "Unknown" gets variant="neutral" (no color).
 */
export default function StatusBadge({ variant, children, dot, className = '' }: StatusBadgeProps) {
  const v = VARIANTS[variant] || VARIANTS.neutral;

  return (
    <span
      className={`status-badge ${className}`}
      style={{ backgroundColor: v.bg, color: v.color }}
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
