// === FILE 2 ===
/**
 * RiskBadge
 * =========
 *
 * Single source of truth for rendering a canonical {@link RiskLabel} in
 * the UI. Every label has a fixed color — never let callers override the
 * palette, the whole point of a shared badge is consistency across the
 * dashboard, identity list, detail pages, and PDF exports.
 *
 * Optional `score` is rendered in parentheses after the label
 * (e.g. `High (72.5)`). The score is formatted to one decimal and is
 * never truncated or rounded to an integer — a 50.0 vs 74.9 difference
 * matters for CISO triage.
 */

import type { JSX } from 'react';
import type { RiskLabel } from '../../types/identity';

/** Props for {@link RiskBadge}. */
export interface RiskBadgeProps {
  /** Canonical risk bucket. */
  label: RiskLabel;
  /** Optional numeric score; rendered in parentheses after the label. */
  score?: number;
  /** Visual size — matches the 3 densities used across the app. */
  size?: 'sm' | 'md' | 'lg';
  /** Optional extra class names (merged after the variant styles). */
  className?: string;
}

// ---------------------------------------------------------------------------
// Tunables — no inline magic strings below this block
// ---------------------------------------------------------------------------

/** Tailwind classes per risk label. Order matches the RiskLabel union. */
const RISK_LABEL_CLASSES: Record<RiskLabel, string> = {
  Critical: 'bg-red-100 text-red-700 border-red-200',
  High: 'bg-orange-100 text-orange-700 border-orange-200',
  Medium: 'bg-yellow-100 text-yellow-700 border-yellow-200',
  Low: 'bg-green-100 text-green-700 border-green-200',
  Info: 'bg-gray-100 text-gray-600 border-gray-200',
};

/** Size → padding + font-size map. */
const SIZE_CLASSES: Record<NonNullable<RiskBadgeProps['size']>, string> = {
  sm: 'px-1.5 py-0.5 text-[10px] leading-4',
  md: 'px-2 py-0.5 text-xs leading-4',
  lg: 'px-2.5 py-1 text-sm leading-5',
};

/** Fixed decimal precision for the optional score chip. */
const SCORE_DECIMALS = 1;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * Render a colored, rounded badge for a risk label. Pure — no hooks,
 * no side effects, safe to render thousands of times in a virtualized
 * table without perf concerns.
 */
export function RiskBadge({
  label,
  score,
  size = 'md',
  className,
}: RiskBadgeProps): JSX.Element {
  const variantClasses = RISK_LABEL_CLASSES[label];
  const sizeClasses = SIZE_CLASSES[size];

  const hasScore = typeof score === 'number' && Number.isFinite(score);
  const formattedScore = hasScore
    ? (score as number).toFixed(SCORE_DECIMALS)
    : null;

  return (
    <span
      role="status"
      aria-label={
        hasScore
          ? `Risk ${label}, score ${formattedScore}`
          : `Risk ${label}`
      }
      data-risk-label={label}
      className={[
        'inline-flex items-center gap-1 rounded-full border font-semibold whitespace-nowrap',
        variantClasses,
        sizeClasses,
        className ?? '',
      ]
        .filter(Boolean)
        .join(' ')}
    >
      <span>{label}</span>
      {formattedScore !== null ? (
        <span className="tabular-nums opacity-80">({formattedScore})</span>
      ) : null}
    </span>
  );
}

export default RiskBadge;
